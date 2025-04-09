#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { LlmServiceInfraStack } from "../lib/llm-service-infra-stack";
import { CicdPipelineStack } from "../lib/cicd-pipeline-stack";

const app = new cdk.App();

// Deploy CI/CD pipeline stack
new CicdPipelineStack(app, "LlmServiceCicdPipelineStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  description: "CI/CD pipeline for LLM Service",
});

// Deploy infrastructure stack (this is typically deployed by the pipeline)
// Only include this for initial deployment or testing
if (process.env.MANUAL_DEPLOY === "true") {
  new LlmServiceInfraStack(app, "LlmServiceInfraStack", {
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_DEFAULT_REGION,
    },
    description: "Infrastructure for LLM Service",
  });
}

app.synth();