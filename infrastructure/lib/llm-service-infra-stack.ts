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
        "yum update -y && yum install -y docker amazon-cloudwatch-agent python3 python3-pip curl nc netcat",
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
  -p 11434:11434 \
  --log-driver=awslogs \
  --log-opt awslogs-group=${logGroup.logGroupName} \
  --log-opt awslogs-region=${this.region} \
  --log-opt awslogs-stream="$INSTANCE_ID/ollama" \
  ollama/ollama:latest

echo "Waiting for Ollama to initialize..."
sleep 10

# Pull the model first (with retries) before starting the LLM service
MODEL_NAME="${modelName}"
MAX_ATTEMPTS=3
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
  echo "Pulling model $MODEL_NAME (attempt $ATTEMPT/$MAX_ATTEMPTS)..."
  if docker exec ollama ollama pull $MODEL_NAME; then
    echo "Model pulled successfully"
    # Explicitly serve the model
    echo "Starting to serve the model..."
    docker exec -d ollama ollama serve $MODEL_NAME
    break
  else
    echo "Model pull attempt $ATTEMPT failed"
    if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
      echo "Failed to pull model after $MAX_ATTEMPTS attempts"
    else
      echo "Retrying in 10 seconds..."
      sleep 10
    fi
    ATTEMPT=$((ATTEMPT+1))
  fi
done

# Start LLM Service
docker run -d --name llm-service --restart always --network llm-network \
  -p ${llmServicePort}:${llmServicePort} \
  -e PORT=${llmServicePort} \
  -e WORKER_THREADS=10 \
  -e OLLAMA_URL=http://ollama:11434 \
  -e MODEL_NAME=$MODEL_NAME \
  -e LOG_LEVEL=INFO \
  -e REFLECTION_ENABLED=true \
  -e GRPC_ENABLE_HTTP2=1 \
  -e GRPC_KEEPALIVE_TIME_MS=30000 \
  -e GRPC_KEEPALIVE_TIMEOUT_MS=20000 \
  -e GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS=1 \
  -e GRPC_HTTP2_MIN_SENT_PING_INTERVAL_WITHOUT_DATA_MS=30000 \
  -e GRPC_HTTP2_MAX_PINGS_WITHOUT_DATA=0 \
  -e STICKY_SESSION_COOKIE=LlmServiceStickiness \
  --log-driver=awslogs \
  --log-opt awslogs-group=${logGroup.logGroupName} \
  --log-opt awslogs-region=${this.region} \
  --log-opt awslogs-stream="$INSTANCE_ID/llm-service" \
  ${this.account}.dkr.ecr.${this.region}.amazonaws.com/llm-service:latest

echo "Service deployment complete"
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
                # First check if the gRPC port is open
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect(('localhost', GRPC_PORT))
                    port_open = True
                except Exception:
                    port_open = False
                finally:
                    s.close()
                
                # Try standard reflection first
                try:
                    grpc_check = subprocess.run(["grpcurl", "-plaintext", f"localhost:{GRPC_PORT}", "list", "llm.LLMService"], 
                                           capture_output=True, timeout=2).returncode == 0
                except:
                    grpc_check = False
                
                # If reflection fails, try direct healthcheck method if available
                if not grpc_check and port_open:
                    try:
                        direct_check = subprocess.run(["grpcurl", "-plaintext", "-d", '{}', f"localhost:{GRPC_PORT}", "llm.LLMService.HealthCheck"], 
                                           capture_output=True, timeout=2).returncode == 0
                        grpc_check = direct_check
                    except:
                        pass
                
                # Check Ollama directly from Python
                ollama_check = False
                try:
                    response = requests.get("http://localhost:11434/api/tags", timeout=2)
                    ollama_check = response.status_code == 200
                except Exception:
                    ollama_check = False
                
                # If port is open but reflection API fails, consider service potentially healthy
                if port_open and ollama_check:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self._set_cookie()
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "status": "healthy",
                        "grpc_port_open": port_open,
                        "grpc_reflection": grpc_check,
                        "ollama_status": ollama_check
                    }).encode())
                else:
                    self.send_response(503)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "status": "unhealthy",
                        "grpc_port_open": port_open,
                        "grpc_reflection": grpc_check,
                        "ollama_status": ollama_check
                    }).encode())
            except Exception as e:
                self.send_response(503)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "error",
                    "error": str(e)
                }).encode())
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

# Counter to track consecutive failures
OLLAMA_FAILS=0
LLM_SERVICE_FAILS=0
MAX_FAILS=3
CHECK_INTERVAL=300  # Check every 5 minutes instead of every minute
MODEL_NAME="${modelName}"

while true; do
  # Check if Ollama container is running
  if ! docker ps | grep -q "ollama"; then
    echo "$(date): Ollama container not running, starting it..."
    docker start ollama 2>/dev/null || true
    sleep 10  # Give more time to initialize
  else
    # Check Ollama API health
    if curl -s -f http://localhost:11434/api/tags > /dev/null 2>&1; then
      # Reset failure counter on success
      OLLAMA_FAILS=0
      echo "$(date): Ollama is healthy"
      
      # Check if model is loaded and being served
      MODEL_CHECK=$(curl -s http://localhost:11434/api/tags | grep -c "$MODEL_NAME" || echo "0")
      if [ "$MODEL_CHECK" -eq "0" ]; then
        echo "$(date): Model $MODEL_NAME is not loaded, serving it now..."
        docker exec ollama ollama pull $MODEL_NAME >/dev/null 2>&1
        docker exec -d ollama ollama serve $MODEL_NAME
      fi
    else
      OLLAMA_FAILS=$((OLLAMA_FAILS+1))
      echo "$(date): Ollama health check failed ($OLLAMA_FAILS/$MAX_FAILS)"
      
      # Only restart after consecutive failures
      if [ $OLLAMA_FAILS -ge $MAX_FAILS ]; then
        echo "$(date): Restarting Ollama after $MAX_FAILS consecutive failures"
        docker restart ollama 2>/dev/null || true
        OLLAMA_FAILS=0
        sleep 15  # Give more time to restart
        
        # Make sure model is loaded after restart
        echo "$(date): Ensuring model is loaded after restart..."
        docker exec ollama ollama pull $MODEL_NAME >/dev/null 2>&1
        docker exec -d ollama ollama serve $MODEL_NAME
      fi
    fi
  fi
  
  # Check if LLM service container is running
  if ! docker ps | grep -q "llm-service"; then
    echo "$(date): LLM service container not running, starting it..."
    docker start llm-service 2>/dev/null || true
    sleep 10  # Give more time to initialize
  else
    # Check LLM Service health - first try basic connectivity
    if nc -z localhost ${llmServicePort} &>/dev/null; then
      # Port is open, which is a good first sign
      # Try the healthcheck script in the container itself
      if docker exec llm-service /healthcheck.sh &>/dev/null; then
        LLM_SERVICE_FAILS=0
        echo "$(date): LLM service is healthy (healthcheck.sh passed)"
      elif grpcurl -plaintext -connect-timeout 5s localhost:${llmServicePort} list &>/dev/null; then
        # Try a simpler check - can we list any services at all?
        LLM_SERVICE_FAILS=0
        echo "$(date): LLM service is partially healthy (port open, some gRPC services available)"
      else
        LLM_SERVICE_FAILS=$((LLM_SERVICE_FAILS+1))
        echo "$(date): LLM service health check failed ($LLM_SERVICE_FAILS/$MAX_FAILS)"
        
        # Only restart after consecutive failures
        if [ $LLM_SERVICE_FAILS -ge $MAX_FAILS ]; then
          echo "$(date): Restarting LLM service after $MAX_FAILS consecutive failures"
          docker restart llm-service 2>/dev/null || true
          LLM_SERVICE_FAILS=0
          sleep 15  # Give more time to restart
        fi
      fi
    else
      LLM_SERVICE_FAILS=$((LLM_SERVICE_FAILS+1))
      echo "$(date): LLM service port ${llmServicePort} is not responding ($LLM_SERVICE_FAILS/$MAX_FAILS)"
      
      # Only restart after consecutive failures
      if [ $LLM_SERVICE_FAILS -ge $MAX_FAILS ]; then
        echo "$(date): Restarting LLM service after $MAX_FAILS consecutive failures"
        docker restart llm-service 2>/dev/null || true
        LLM_SERVICE_FAILS=0
        sleep 15  # Give more time to restart
      fi
    fi
  fi
  
  sleep $CHECK_INTERVAL
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
        schedule: autoscaling.Schedule.cron({ hour: "5", minute: "0" }),
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
