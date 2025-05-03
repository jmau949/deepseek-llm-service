import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import * as ssm from "aws-cdk-lib/aws-ssm";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as elasticloadbalancingv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import { Construct } from "constructs";
import * as fs from "fs";
import * as path from "path";

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

      // Retrieve custom domain information
      const certificateDomain = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesCertificateDomain`
      );

      const certificateArn = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesCertificateArn`
      );

      // Get multiple subnet IDs for multi-AZ deployment
      const availableSubnetIds: string[] = [];

      // First, try to determine the number of private subnets by reading the count parameter
      try {
        // Get the actual number of private subnets from the VPC stack
        // This approach avoids trying to fetch non-existent parameters
        const maxAzs =
          Number(
            ssm.StringParameter.valueForStringParameter(
              this,
              `${serviceDiscoveryPrefix}/SharedAiServicesMaxAzs`
            )
          ) || 2; // Default to 2 if parameter doesn't exist

        console.log(`VPC was created with ${maxAzs} AZs`);

        // Now we know exactly how many subnets to look for
        for (let i = 1; i <= maxAzs; i++) {
          try {
            const subnetId = ssm.StringParameter.valueForStringParameter(
              this,
              `${serviceDiscoveryPrefix}/SharedAiServicesPrivateSubnet${i}Id`
            );
            availableSubnetIds.push(subnetId);
            console.log(`Found private subnet ${i}: ${subnetId}`);
          } catch (error) {
            console.log(`Warning: Could not find private subnet ${i}`);
          }
        }
      } catch (error) {
        console.log(
          "Could not determine exact subnet count, falling back to manual detection"
        );

        // Fallback: Try to get each subnet ID individually
        // This is the original approach, but limited to just the first 3 subnets to avoid
        // excessive parameter fetching that might fail
        for (let i = 1; i <= 3; i++) {
          try {
            const subnetId = ssm.StringParameter.valueForStringParameter(
              this,
              `${serviceDiscoveryPrefix}/SharedAiServicesPrivateSubnet${i}Id`
            );
            availableSubnetIds.push(subnetId);
          } catch (error) {
            // No more subnet parameters found, exit the loop
            console.log(`No subnet found at index ${i}, stopping search`);
            break;
          }
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

      // Calculate the number of AZs based on the subnets we found
      // For the VPC created with 2 AZs and 2 subnet types (public and private),
      // each AZ has 1 private subnet, so we divide by 1
      const requiredAzs = Math.min(2, availableSubnetIds.length);
      const availabilityZones = cdk.Stack.of(this).availabilityZones.slice(
        0,
        requiredAzs
      );

      console.log(
        `Using ${requiredAzs} availability zones: ${availabilityZones.join(
          ", "
        )}`
      );

      const vpc = ec2.Vpc.fromVpcAttributes(this, "SharedVpc", {
        vpcId: vpcId,
        // Use only the number of AZs that match our subnet count
        availabilityZones: availabilityZones,
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
        elasticloadbalancingv2.ApplicationTargetGroup.fromTargetGroupAttributes(
          this,
          "LlmServiceTargetGroup",
          {
            targetGroupArn: targetGroupArn,
          }
        );

      // Import certificate for the custom domain
      const certificate = acm.Certificate.fromCertificateArn(
        this,
        "DeepseekCertificate",
        certificateArn
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
       * Scripts S3 Bucket
       *
       * Creating an S3 bucket to store instance scripts since they exceed
       * the 16KB user data limit
       */
      const scriptsBucket = new s3.Bucket(this, "LlmServiceScriptsBucket", {
        removalPolicy: cdk.RemovalPolicy.DESTROY,
        autoDeleteObjects: true,
        encryption: s3.BucketEncryption.S3_MANAGED,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        enforceSSL: true,
      });

      // Get script content from files
      const scriptsPath = path.join(__dirname, "..", "scripts");

      // Deploy the scripts to S3 bucket
      new s3deploy.BucketDeployment(this, "DeployScripts", {
        sources: [s3deploy.Source.asset(scriptsPath)],
        destinationBucket: scriptsBucket,
      });

      /**
       * EC2 Instance Role
       *
       * Create an IAM role for the EC2 instances with least privilege permissions:
       * - Pull container images from ECR
       * - Allow SSM Session Manager access (for debugging)
       * - CloudWatch Logs access for logging
       * - Allow access to S3 bucket for scripts
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

      // Add permissions to access S3 bucket for scripts
      instanceRole.addToPrincipalPolicy(
        new iam.PolicyStatement({
          actions: ["s3:GetObject", "s3:ListBucket"],
          resources: [scriptsBucket.bucketArn, `${scriptsBucket.bucketArn}/*`],
        })
      );

      // Service definitions - these are small enough to be included in user data
      const healthProxyService = `[Unit]
Description=HTTP/2 Health Check Proxy
After=docker.service network.target
Requires=docker.service

[Service]
Type=simple
ExecStartPre=/bin/bash -c "pip3 install -U h2 hyper requests"
ExecStart=/usr/bin/python3 /opt/health-proxy/health.py ${llmServicePort}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target`;

      const containerWatchdogService = `[Unit]
Description=Container Watchdog
After=docker.service
Requires=docker.service

[Service]
Environment="MODEL_NAME=${modelName}"
Environment="PORT=${llmServicePort}"
ExecStart=/opt/llm-service/watchdog.sh
Restart=always

[Install]
WantedBy=multi-user.target`;

      /**
       * EC2 User Data - streamlined version that downloads scripts from S3
       * and passes environment variables to them
       */
      const userData = ec2.UserData.forLinux();
      userData.addCommands(
        "yum update -y && yum install -y docker amazon-cloudwatch-agent python3 python3-pip curl nc netcat",
        "systemctl start docker && systemctl enable docker",
        "pip3 install h2 hyper requests",

        // Create directories
        "mkdir -p /opt/{llm-service,health-proxy/certs} /var/log",
        "curl -sSL https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz | tar -xz -C /usr/local/bin grpcurl",

        // Install dependencies with compatible versions
        "pip3 install 'urllib3<2.0' 'cryptography<40.0.0' 'pyopenssl<23.0.0' 'requests'",

        // Get instance ID for logging
        "INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)",
        'echo "Instance ID: $INSTANCE_ID" > /var/log/instance-id.log',

        // Configure CloudWatch agent - minimal config
        `cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {"file_path": "/var/log/messages", "log_group_name": "${logGroup.logGroupName}", "log_stream_name": "#{instance_id}/system"},
          {"file_path": "/var/log/docker", "log_group_name": "${logGroup.logGroupName}", "log_stream_name": "#{instance_id}/docker"}
        ]
      }
    }
  }
}
EOF`,
        "systemctl start amazon-cloudwatch-agent && systemctl enable amazon-cloudwatch-agent",

        // Login to ECR
        `aws ecr get-login-password --region ${this.region} | docker login --username AWS --password-stdin ${this.account}.dkr.ecr.${this.region}.amazonaws.com`,

        // Download scripts from S3
        `aws s3 cp s3://${scriptsBucket.bucketName}/start.sh /opt/llm-service/start.sh`,
        `aws s3 cp s3://${scriptsBucket.bucketName}/health.py /opt/health-proxy/health.py`,
        `aws s3 cp s3://${scriptsBucket.bucketName}/watchdog.sh /opt/llm-service/watchdog.sh`,

        // Set executable permissions
        "chmod +x /opt/llm-service/start.sh /opt/health-proxy/health.py /opt/llm-service/watchdog.sh",

        // Create systemd service files
        `cat > /etc/systemd/system/health-proxy.service << 'EOF'
${healthProxyService}
EOF`,

        `cat > /etc/systemd/system/container-watchdog.service << 'EOF'
${containerWatchdogService}
EOF`,

        // Set environment variables and run startup script
        `export MODEL_NAME="${modelName}"`,
        `export PORT="${llmServicePort}"`,
        `export LOG_GROUP_NAME="${logGroup.logGroupName}"`,
        `export REGION="${this.region}"`,
        `export ECR_REPO="${this.account}.dkr.ecr.${this.region}.amazonaws.com"`,
        "cd /opt/llm-service && ./start.sh || exit 1", // Fail the instance if script fails

        // Start the monitoring services
        "systemctl daemon-reload",
        "systemctl enable health-proxy container-watchdog",
        "systemctl start health-proxy container-watchdog || exit 1" // Fail if services can't start
      );

      /**
       * Launch Template
       *
       * Define how EC2 instances should be launched:
       * - Machine image (Amazon Linux 2)
       * - Instance type (GPU optimized for ML workloads)
       * - User data script
       * - Security group
       * - IAM role
       */
      const launchTemplate = new ec2.LaunchTemplate(
        this,
        "LlmServiceLaunchTemplate",
        {
          machineImage: ec2.MachineImage.latestAmazonLinux2(),
          instanceType: new ec2.InstanceType("c5.2xlarge"), // GPU instance for model inference
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
        maxCapacity: 1, // Increased to allow for scale out during high demand
        instanceMonitoring: autoscaling.Monitoring.BASIC, // Basic monitoring to save costs
        updatePolicy: autoscaling.UpdatePolicy.rollingUpdate({
          maxBatchSize: 1,
          minInstancesInService: 0, // Keep at least one instance running during updates
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
       * - Scale down to minimum at 12am Central Time (6am UTC)
       * - Scale up to normal capacity at 9am Central Time (3pm UTC)
       */
      asg.scaleOnSchedule("ScaleDownAtMidnight", {
        schedule: autoscaling.Schedule.cron({ hour: "5", minute: "0" }),
        minCapacity: 0,
        maxCapacity: 0,
      });

      asg.scaleOnSchedule("ScaleUpAtNineAM", {
        schedule: autoscaling.Schedule.cron({ hour: "15", minute: "0" }),
        minCapacity: 0,
        maxCapacity: 0,
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

      new cdk.CfnOutput(this, "CertificateDomain", {
        value: certificateDomain,
        description: "The domain name used for the LLM service",
        exportName: "DeepseekLlmServiceDomain",
      });

      new cdk.CfnOutput(this, "ScriptsBucketName", {
        value: scriptsBucket.bucketName,
        description: "The name of the S3 bucket containing the service scripts",
        exportName: "DeepseekLlmServiceScriptsBucketName",
      });
    } catch (error) {
      console.error("Error retrieving SSM parameters:", error);
      throw new Error(`Failed to initialize LlmServiceInfraStack: ${error}`);
    }
  }
}
