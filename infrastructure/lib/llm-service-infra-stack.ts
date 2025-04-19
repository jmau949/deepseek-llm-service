import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import * as ssm from "aws-cdk-lib/aws-ssm";
import * as elasticloadbalancingv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import { Construct } from "constructs";

/**
 * Properties for the LLM Service Infrastructure Stack
 *
 * This stack creates the GPU instances running the LLM service
 * within the VPC created by the VpcInfrastructureStack
 */
export interface LlmServiceInfraStackProps extends cdk.StackProps {
  /** Optional environment name for resource naming */
  environmentName?: string;
  /** Prefix for SSM parameters to reference shared infrastructure */
  serviceDiscoveryPrefix?: string;
  /** Port used by the LLM service (default: 50051) */
  llmServicePort?: number;
  /** Model name to be loaded by the LLM service (default: deepseek-r1:1.5b) */
  modelName?: string;
}

export class LlmServiceInfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: LlmServiceInfraStackProps) {
    super(scope, id, props);

    // Use provided values or defaults
    const serviceDiscoveryPrefix =
      props?.serviceDiscoveryPrefix || "/deepseek-llm-service";
    const llmServicePort = props?.llmServicePort || 50051;
    const modelName = props?.modelName || "deepseek-r1:1.5b";

    try {
      /**
       * Retrieve Shared Infrastructure Values from SSM Parameter Store
       *
       * These values were stored by the VpcInfrastructureStack and
       * are used to reference existing resources
       */
      const vpcId = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesVpcId`
      );

      const llmServiceSgId = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesLlmServiceSgId`
      );

      const targetGroupArn = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesTargetGroupArn`
      );

      const vpcCidrBlock = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesVpcCidrBlock`
      );

      // Get multiple subnet IDs for multi-AZ deployment
      const availableSubnetIds: string[] = [];

      // Try to get subnet IDs, starting from 1 and increment until we can't find more
      let subnetCounter = 1;
      let continueLooping = true;

      while (continueLooping) {
        try {
          const subnetId = ssm.StringParameter.valueForStringParameter(
            this,
            `${serviceDiscoveryPrefix}/SharedAiServicesPrivateSubnet${subnetCounter}Id`
          );
          availableSubnetIds.push(subnetId);
          subnetCounter++;
        } catch (error) {
          // No more subnet parameters found, exit the loop
          continueLooping = false;
        }
      }

      // Ensure we have at least one subnet
      if (availableSubnetIds.length === 0) {
        throw new Error("No private subnets found in SSM Parameter Store");
      }

      console.log(
        `Found ${
          availableSubnetIds.length
        } private subnet(s): ${availableSubnetIds.join(", ")}`
      );

      /**
       * Import VPC and Related Resources
       *
       * Rather than creating new resources, we're importing existing
       * resources created by the VpcInfrastructureStack
       */
      const vpc = ec2.Vpc.fromVpcAttributes(this, "SharedVpc", {
        vpcId: vpcId,
        // Use all available AZs from the account
        availabilityZones: cdk.Stack.of(this).availabilityZones,
        // Use all the private subnets we found
        privateSubnetIds: availableSubnetIds,
      });

      // Import security group from the shared infrastructure
      const llmServiceSg = ec2.SecurityGroup.fromSecurityGroupId(
        this,
        "LlmServiceSg",
        llmServiceSgId
      );

      // Import the target group from the shared infrastructure
      const targetGroup =
        elasticloadbalancingv2.ApplicationTargetGroup.fromTargetGroupArn(
          this,
          "LlmServiceTargetGroup",
          targetGroupArn
        );

      /**
       * EC2 Instance Role
       *
       * Create an IAM role for the EC2 instances with least privilege permissions:
       * - Pull container images from ECR
       * - Allow SSM Session Manager access (for debugging)
       * - CloudWatch Logs access for logging
       */
      const instanceRole = new iam.Role(this, "LlmServiceInstanceRole", {
        assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
        managedPolicies: [
          // Allow SSM Session Manager for secure instance access without SSH
          iam.ManagedPolicy.fromAwsManagedPolicyName(
            "AmazonSSMManagedInstanceCore"
          ),
        ],
      });

      // Add minimum required permissions
      instanceRole.addToPrincipalPolicy(
        new iam.PolicyStatement({
          actions: [
            // ECR permissions to pull container images
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetAuthorizationToken",
          ],
          resources: ["*"], // Limiting resource scope for some of these actions is not possible
        })
      );

      // Add permissions for CloudWatch Logs
      instanceRole.addToPrincipalPolicy(
        new iam.PolicyStatement({
          actions: [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogStreams",
          ],
          resources: ["arn:aws:logs:*:*:*"],
        })
      );

      /**
       * Create Log Group for Instance Logs
       *
       * Set up a CloudWatch Log Group for container and instance logs
       * with appropriate retention period
       */
      const logGroup = new logs.LogGroup(this, "LlmServiceLogGroup", {
        retention: logs.RetentionDays.ONE_WEEK,
        removalPolicy: cdk.RemovalPolicy.DESTROY, // Automatically delete logs when stack is deleted
      });

      /**
       * EC2 User Data
       *
       * Define the startup script that will:
       * 1. Install Docker
       * 2. Pull the LLM service container
       * 3. Run the container with the correct configuration
       *
       * No service discovery registration is needed anymore since
       * instances will be registered to the ALB target group automatically
       */
      const userData = ec2.UserData.forLinux();
      userData.addCommands(
        "yum update -y",
        "yum install -y docker amazon-cloudwatch-agent",
        "systemctl start docker",
        "systemctl enable docker",

        // Configure CloudWatch agent
        `cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/messages",
            "log_group_name": "${logGroup.logGroupName}",
            "log_stream_name": "{instance_id}/system",
            "retention_in_days": 7
          },
          {
            "file_path": "/var/log/docker",
            "log_group_name": "${logGroup.logGroupName}",
            "log_stream_name": "{instance_id}/docker",
            "retention_in_days": 7
          }
        ]
      }
    }
  }
}
EOF`,
        "systemctl start amazon-cloudwatch-agent",
        "systemctl enable amazon-cloudwatch-agent",

        // Pull and run the LLM service container
        `aws ecr get-login-password --region ${this.region} | docker login --username AWS --password-stdin ${this.account}.dkr.ecr.${this.region}.amazonaws.com`,
        `docker pull ${this.account}.dkr.ecr.${this.region}.amazonaws.com/llm-service:latest`,

        // Run the container with environment variables
        `docker run -d --name llm-service --restart always \
          -p ${llmServicePort}:${llmServicePort} \
          -e MODEL_NAME="${modelName}" \
          --log-driver=awslogs \
          --log-opt awslogs-group=${logGroup.logGroupName} \
          --log-opt awslogs-region=${this.region} \
          --log-opt awslogs-stream={instance_id}/llm-service \
          ${this.account}.dkr.ecr.${this.region}.amazonaws.com/llm-service:latest`,

        // Configure health check endpoint for ALB
        `docker run -d --name health-check --restart always \
          -p 80:80 \
          --entrypoint "/bin/sh" \
          amazon/amazon-ecs-sample \
          -c "echo 'health check service for LLM' > /tmp/index.html && cd /tmp && python -m http.server 80"`
      );

      /**
       * Launch Template
       *
       * Define how EC2 instances should be launched:
       * - Machine image (Amazon Linux 2)
       * - Instance type (compute optimized for ML workloads)
       * - User data script
       * - Security group
       * - IAM role
       * - Spot instances for cost savings
       */
      const launchTemplate = new ec2.LaunchTemplate(
        this,
        "LlmServiceLaunchTemplate",
        {
          machineImage: ec2.MachineImage.latestAmazonLinux2(),
          instanceType: new ec2.InstanceType("c5.2xlarge"), // Adjust for your GPU/workload requirements
          userData,
          securityGroup: llmServiceSg,
          role: instanceRole,
          spotOptions: {
            requestType: ec2.SpotRequestType.ONE_TIME,
            maxPrice: 0.25, // Set your max price
          },
          blockDevices: [
            {
              deviceName: "/dev/xvda",
              volume: ec2.BlockDeviceVolume.ebs(30, {
                encrypted: true,
                volumeType: ec2.EbsDeviceVolumeType.GP3,
              }),
            },
          ],
        }
      );

      /**
       * Auto Scaling Group
       *
       * Create an ASG that will:
       * 1. Launch instances across multiple AZs for high availability
       * 2. Register instances with the ALB target group automatically
       * 3. Scale based on demand
       * 4. Follow a schedule for cost optimization
       */

      // Create a map of subnets for the ASG to use
      const subnetSelection: ec2.SubnetSelection = {
        subnets: availableSubnetIds.map((id, index) =>
          ec2.Subnet.fromSubnetId(this, `PrivateSubnet${index + 1}`, id)
        ),
      };

      const asg = new autoscaling.AutoScalingGroup(this, "LlmServiceAsg", {
        vpc,
        vpcSubnets: subnetSelection,
        launchTemplate,
        minCapacity: 1,
        maxCapacity: 1, // Allow scaling to 2 instances max
        desiredCapacity: 1, // Start with 1 instance
        instanceMonitoring: autoscaling.Monitoring.BASIC, // Basic monitoring to save costs
        healthCheck: autoscaling.HealthCheck.elb({
          grace: cdk.Duration.minutes(5),
        }),
        updatePolicy: autoscaling.UpdatePolicy.rollingUpdate({
          maxBatchSize: 1,
          minInstancesInService: 0,
          pauseTime: cdk.Duration.minutes(5),
        }),
      });

      /**
       * Register ASG with Target Group
       *
       * This is the key connection that replaces service discovery:
       * - Instances are automatically registered with the ALB target group
       * - ALB performs health checks and routes traffic only to healthy instances
       * - When instances scale in/out, the ALB target group is automatically updated
       */
      asg.attachToApplicationTargetGroup(targetGroup);

      /**
       * Auto Scaling Policies
       *
       * Define how the ASG should scale:
       * - Scale based on CPU utilization (ML workloads are CPU intensive)
       * - Target tracking policy maintains CPU around 70%
       */
      asg.scaleOnCpuUtilization("CpuScaling", {
        targetUtilizationPercent: 70,
        cooldown: cdk.Duration.seconds(300),
      });

      /**
       * Scheduled Scaling
       *
       * Implement cost-saving measures by scaling down during off-hours:
       * - Stop instances at 12am Central Time (6am UTC)
       * - Start instances at 9am Central Time (3pm UTC)
       */
      asg.scaleOnSchedule("StopAtMidnight", {
        schedule: autoscaling.Schedule.cron({ hour: "6", minute: "0" }),
        minCapacity: 0,
        maxCapacity: 0,
        desiredCapacity: 0,
      });

      asg.scaleOnSchedule("StartAtNineAM", {
        schedule: autoscaling.Schedule.cron({ hour: "15", minute: "0" }),
        minCapacity: 1,
        maxCapacity: 1,
        desiredCapacity: 1,
      });

      /**
       * Stack Outputs
       *
       * Export important resources for cross-stack references
       * and for visibility in the CloudFormation console
       */
      new cdk.CfnOutput(this, "VpcId", {
        value: vpcId,
        description: "The ID of the VPC",
      });

      new cdk.CfnOutput(this, "TargetGroupArn", {
        value: targetGroup.targetGroupArn,
        description: "Target Group ARN for LLM Service",
      });

      new cdk.CfnOutput(this, "AsgName", {
        value: asg.autoScalingGroupName,
        description: "The name of the Auto Scaling Group",
        exportName: "DeepseekLlmServiceAsgName",
      });

      new cdk.CfnOutput(this, "LogGroupName", {
        value: logGroup.logGroupName,
        description: "The name of the CloudWatch Log Group",
        exportName: "DeepseekLlmServiceLogGroupName",
      });
    } catch (error) {
      console.error("Error retrieving SSM parameters:", error);
      throw new Error(`Failed to initialize LlmServiceInfraStack: ${error}`);
    }
  }
}
