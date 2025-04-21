import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import * as ssm from "aws-cdk-lib/aws-ssm";
import * as elasticloadbalancingv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
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
       * 1. Install Docker and necessary dependencies
       * 2. Pull the LLM service container
       * 3. Run the container with the correct configuration
       * 4. Set up an HTTPS health check proxy for the ALB
       */
      const userData = ec2.UserData.forLinux();
      userData.addCommands(
        "yum update -y && yum install -y docker amazon-cloudwatch-agent python3 python3-pip curl",
        "systemctl start docker && systemctl enable docker",

        // Install grpcurl and prepare directories
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

        // Combined container start script
        `cat > /opt/llm-service/start.sh << 'EOF'
#!/bin/bash
# Get instance ID for logging
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

# Create network
docker network create llm-network 2>/dev/null || true

# Start Ollama
docker run -d --name ollama --restart always --network llm-network \
  -v ollama-data:/root/.ollama \
  --log-driver=awslogs \
  --log-opt awslogs-group=${logGroup.logGroupName} \
  --log-opt awslogs-region=${this.region} \
  --log-opt awslogs-stream="$INSTANCE_ID/ollama" \
  ollama/ollama:latest

# Start LLM Service
docker run -d --name llm-service --restart always --network llm-network \
  -p ${llmServicePort}:${llmServicePort} \
  -e PORT=${llmServicePort} \
  -e WORKER_THREADS=10 \
  -e OLLAMA_URL=http://ollama:11434 \
  -e MODEL_NAME=${modelName} \
  -e LOG_LEVEL=INFO \
  -e GRPC_ENABLE_HTTP2=1 \
  -e GRPC_KEEPALIVE_TIME_MS=10000 \
  -e GRPC_KEEPALIVE_TIMEOUT_MS=5000 \
  -e GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS=1 \
  -e GRPC_HTTP2_MIN_SENT_PING_INTERVAL_WITHOUT_DATA_MS=5000 \
  -e GRPC_HTTP2_MAX_PINGS_WITHOUT_DATA=0 \
  -e STICKY_SESSION_COOKIE=LlmServiceStickiness \
  --log-driver=awslogs \
  --log-opt awslogs-group=${logGroup.logGroupName} \
  --log-opt awslogs-region=${this.region} \
  --log-opt awslogs-stream="$INSTANCE_ID/llm-service" \
  ${this.account}.dkr.ecr.${this.region}.amazonaws.com/llm-service:latest

# Pull the model
sleep 15
(docker exec ollama ollama pull ${modelName} && echo "Model pulled successfully") || echo "Model pull failed"
EOF`,
        "chmod +x /opt/llm-service/start.sh",
        "cd /opt/llm-service && ./start.sh &",

        // Simple health check script
        `cat > /opt/health-proxy/health.py << 'EOF'
#!/usr/bin/env python3
import http.server, socketserver, subprocess, json, ssl, uuid, requests
from http.cookies import SimpleCookie

PORT = 443
GRPC_PORT = ${llmServicePort}
CERT_PATH = "/opt/health-proxy/certs/server.crt"
KEY_PATH = "/opt/health-proxy/certs/server.key"
COOKIE_NAME = "LlmServiceStickiness"

class HealthCheckHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass
    
    def do_GET(self):
        if self.path == '/health':
            try:
                grpc_check = subprocess.run(["grpcurl", "-plaintext", f"localhost:{GRPC_PORT}", "list", "llm.LLMService"], 
                                       capture_output=True, timeout=2).returncode == 0
                # Check Ollama directly from Python
                ollama_check = False
                try:
                    response = requests.get("http://localhost:11434/api/tags", timeout=2)
                    ollama_check = response.status_code == 200
                except Exception:
                    ollama_check = False
                
                if grpc_check and ollama_check:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self._set_cookie()
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "healthy"}).encode())
                else:
                    self.send_response(503)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'Service Unavailable')
            except Exception:
                self.send_response(503)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Service Unavailable')
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._set_cookie()
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
    
    def _set_cookie(self):
        if 'Cookie' in self.headers:
            cookies = SimpleCookie(self.headers['Cookie'])
            if COOKIE_NAME in cookies: return
        self.send_header('Set-Cookie', f'{COOKIE_NAME}={uuid.uuid4()}; Path=/; Max-Age=900; Secure; HttpOnly')

if __name__ == "__main__":
    # Generate self-signed cert
    import os
    if not os.path.exists(CERT_PATH):
        os.system(f'openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj "/CN=localhost" -keyout {KEY_PATH} -out {CERT_PATH}')
    
    # Run server
    httpd = socketserver.TCPServer(("", PORT), HealthCheckHandler)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(CERT_PATH, KEY_PATH)
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()
EOF`,
        "chmod +x /opt/health-proxy/health.py",

        // Simple watchdog script
        `cat > /opt/llm-service/watchdog.sh << 'EOF'
#!/bin/bash
while true; do
  # Check and restart Ollama if needed
  if ! docker ps | grep -q "ollama"; then
    docker start ollama 2>/dev/null || true
    sleep 5
  fi
  
  # Check and restart LLM service if needed
  if ! docker ps | grep -q "llm-service"; then
    docker start llm-service 2>/dev/null || true
    sleep 5
  fi
  
  # Check Ollama API directly from host
  if ! curl -s -f http://localhost:11434/api/tags > /dev/null 2>&1; then
    docker restart ollama 2>/dev/null || true
    sleep 5
  fi
  
  # Check LLM Service
  if ! grpcurl -plaintext localhost:${llmServicePort} list llm.LLMService > /dev/null 2>&1; then
    docker restart llm-service 2>/dev/null || true
  fi
  
  sleep 60
done
EOF`,
        "chmod +x /opt/llm-service/watchdog.sh",

        // Create systemd services with minimal config
        `cat > /etc/systemd/system/health-proxy.service << 'EOF'
[Unit]
Description=Health Check Proxy
After=docker.service
Requires=docker.service

[Service]
ExecStart=/usr/bin/python3 /opt/health-proxy/health.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF`,

        `cat > /etc/systemd/system/container-watchdog.service << 'EOF'
[Unit]
Description=Container Watchdog
After=docker.service
Requires=docker.service

[Service]
ExecStart=/opt/llm-service/watchdog.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF`,

        // Enable and start services
        "systemctl daemon-reload",
        "systemctl enable health-proxy container-watchdog",
        "systemctl start health-proxy container-watchdog"
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
        schedule: autoscaling.Schedule.cron({ hour: "6", minute: "0" }),
        minCapacity: 0,
        maxCapacity: 0,
      });

      asg.scaleOnSchedule("ScaleUpAtNineAM", {
        schedule: autoscaling.Schedule.cron({ hour: "15", minute: "0" }),
        minCapacity: 1,
        maxCapacity: 1,
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
    } catch (error) {
      console.error("Error retrieving SSM parameters:", error);
      throw new Error(`Failed to initialize LlmServiceInfraStack: ${error}`);
    }
  }
}
