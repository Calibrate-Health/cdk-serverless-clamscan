"use strict";
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServerlessClamscan = void 0;
const JSII_RTTI_SYMBOL_1 = Symbol.for("jsii.rtti");
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const path = require("path");
const aws_ec2_1 = require("@aws-cdk/aws-ec2");
const aws_efs_1 = require("@aws-cdk/aws-efs");
const aws_events_1 = require("@aws-cdk/aws-events");
const aws_events_targets_1 = require("@aws-cdk/aws-events-targets");
const aws_iam_1 = require("@aws-cdk/aws-iam");
const aws_lambda_1 = require("@aws-cdk/aws-lambda");
const aws_lambda_destinations_1 = require("@aws-cdk/aws-lambda-destinations");
const aws_lambda_event_sources_1 = require("@aws-cdk/aws-lambda-event-sources");
const aws_s3_1 = require("@aws-cdk/aws-s3");
const aws_sqs_1 = require("@aws-cdk/aws-sqs");
const core_1 = require("@aws-cdk/core");
const cdk_nag_1 = require("cdk-nag");
/**
  An [aws-cdk](https://github.com/aws/aws-cdk) construct that uses [ClamAV®](https://www.clamav.net/).
  to scan objects in Amazon S3 for viruses. The construct provides a flexible interface for a system
  to act based on the results of a ClamAV virus scan.

  The construct creates a Lambda function with EFS integration to support larger files.
  A VPC with isolated subnets, a S3 Gateway endpoint will also be created.

  Additionally creates an twice-daily job to download the latest ClamAV definition files to the
  Virus Definitions S3 Bucket by utilizing an EventBridge rule and a Lambda function and
  publishes CloudWatch Metrics to the 'serverless-clamscan' namespace.

  __Important O&M__:
  When ClamAV publishes updates to the scanner you will see “Your ClamAV installation is OUTDATED” in your scan results.
  While the construct creates a system to keep the database definitions up to date, you must update the scanner to
  detect all the latest Viruses.

  Update the docker images of the Lambda functions with the latest version of ClamAV by re-running `cdk deploy`.

  Successful Scan Event format
  ```json
  {
     "source": "serverless-clamscan",
     "input_bucket": <input_bucket_name>,
     "input_key": <object_key>,
     "status": <"CLEAN"|"INFECTED"|"N/A">,
     "message": <scan_summary>,
   }
  ```

  Note: The Virus Definitions bucket policy will likely cause a deletion error if you choose to delete
  the stack associated in the construct. However since the bucket itself gets deleted, you can delete
  the stack again to resolve the error.
 */
class ServerlessClamscan extends core_1.Construct {
    /**
     * Creates a ServerlessClamscan construct.
     * @param scope The parent creating construct (usually `this`).
     * @param id The construct's name.
     * @param props A `ServerlessClamscanProps` interface.
     */
    constructor(scope, id, props) {
        var _b, _c;
        super(scope, id);
        this._efsRootPath = '/lambda';
        this._efsMountPath = `/mnt${this._efsRootPath}`;
        this._efsDefsPath = 'virus_database/';
        if (!props.onResult) {
            this.resultBus = new aws_events_1.EventBus(this, 'ScanResultBus');
            this.resultDest = new aws_lambda_destinations_1.EventBridgeDestination(this.resultBus);
            this.infectedRule = new aws_events_1.Rule(this, 'InfectedRule', {
                eventBus: this.resultBus,
                description: 'Event for when a file is marked INFECTED',
                eventPattern: {
                    detail: {
                        responsePayload: {
                            source: ['serverless-clamscan'],
                            status: ['INFECTED'],
                        },
                    },
                },
            });
            this.cleanRule = new aws_events_1.Rule(this, 'CleanRule', {
                eventBus: this.resultBus,
                description: 'Event for when a file is marked CLEAN',
                eventPattern: {
                    detail: {
                        responsePayload: {
                            source: ['serverless-clamscan'],
                            status: ['CLEAN'],
                        },
                    },
                },
            });
        }
        else {
            this.resultDest = props.onResult;
        }
        if (!props.onError) {
            this.errorDeadLetterQueue = new aws_sqs_1.Queue(this, 'ScanErrorDeadLetterQueue', {
                encryption: aws_sqs_1.QueueEncryption.KMS_MANAGED,
            });
            this.errorDeadLetterQueue.addToResourcePolicy(new aws_iam_1.PolicyStatement({
                actions: ['sqs:*'],
                effect: aws_iam_1.Effect.DENY,
                principals: [new aws_iam_1.AnyPrincipal()],
                conditions: { Bool: { 'aws:SecureTransport': false } },
                resources: [this.errorDeadLetterQueue.queueArn],
            }));
            this.errorQueue = new aws_sqs_1.Queue(this, 'ScanErrorQueue', {
                encryption: aws_sqs_1.QueueEncryption.KMS_MANAGED,
                deadLetterQueue: {
                    maxReceiveCount: 3,
                    queue: this.errorDeadLetterQueue,
                },
            });
            this.errorQueue.addToResourcePolicy(new aws_iam_1.PolicyStatement({
                actions: ['sqs:*'],
                effect: aws_iam_1.Effect.DENY,
                principals: [new aws_iam_1.AnyPrincipal()],
                conditions: { Bool: { 'aws:SecureTransport': false } },
                resources: [this.errorQueue.queueArn],
            }));
            this.errorDest = new aws_lambda_destinations_1.SqsDestination(this.errorQueue);
            cdk_nag_1.NagSuppressions.addResourceSuppressions(this.errorDeadLetterQueue, [
                { id: 'AwsSolutions-SQS3', reason: 'This queue is a DLQ.' },
            ]);
        }
        else {
            this.errorDest = props.onError;
        }
        const vpc = new aws_ec2_1.Vpc(this, 'ScanVPC', {
            subnetConfiguration: [
                {
                    subnetType: aws_ec2_1.SubnetType.PRIVATE_ISOLATED,
                    name: 'Isolated',
                },
            ],
        });
        vpc.addFlowLog('FlowLogs');
        this._s3Gw = vpc.addGatewayEndpoint('S3Endpoint', {
            service: aws_ec2_1.GatewayVpcEndpointAwsService.S3,
        });
        const fileSystem = new aws_efs_1.FileSystem(this, 'ScanFileSystem', {
            vpc: vpc,
            encrypted: props.efsEncryption === false ? false : true,
            lifecyclePolicy: aws_efs_1.LifecyclePolicy.AFTER_7_DAYS,
            performanceMode: aws_efs_1.PerformanceMode.GENERAL_PURPOSE,
            removalPolicy: core_1.RemovalPolicy.DESTROY,
            securityGroup: new aws_ec2_1.SecurityGroup(this, 'ScanFileSystemSecurityGroup', {
                vpc: vpc,
                allowAllOutbound: false,
            }),
        });
        const lambda_ap = fileSystem.addAccessPoint('ScanLambdaAP', {
            createAcl: {
                ownerGid: '1000',
                ownerUid: '1000',
                permissions: '755',
            },
            posixUser: {
                gid: '1000',
                uid: '1000',
            },
            path: this._efsRootPath,
        });
        const logs_bucket = (_b = props.defsBucketAccessLogsConfig) === null || _b === void 0 ? void 0 : _b.logsBucket;
        const logs_bucket_prefix = (_c = props.defsBucketAccessLogsConfig) === null || _c === void 0 ? void 0 : _c.logsPrefix;
        if (logs_bucket === true || logs_bucket === undefined) {
            this.defsAccessLogsBucket = new aws_s3_1.Bucket(this, 'VirusDefsAccessLogsBucket', {
                encryption: aws_s3_1.BucketEncryption.S3_MANAGED,
                removalPolicy: core_1.RemovalPolicy.RETAIN,
                serverAccessLogsPrefix: 'access-logs-bucket-logs',
                blockPublicAccess: {
                    blockPublicAcls: true,
                    blockPublicPolicy: true,
                    ignorePublicAcls: true,
                    restrictPublicBuckets: true,
                },
            });
            this.defsAccessLogsBucket.addToResourcePolicy(new aws_iam_1.PolicyStatement({
                effect: aws_iam_1.Effect.DENY,
                actions: ['s3:*'],
                resources: [
                    this.defsAccessLogsBucket.arnForObjects('*'),
                    this.defsAccessLogsBucket.bucketArn,
                ],
                principals: [new aws_iam_1.AnyPrincipal()],
                conditions: {
                    Bool: {
                        'aws:SecureTransport': false,
                    },
                },
            }));
        }
        else if (logs_bucket != false) {
            this.defsAccessLogsBucket = logs_bucket;
        }
        const defs_bucket = new aws_s3_1.Bucket(this, 'VirusDefsBucket', {
            encryption: aws_s3_1.BucketEncryption.S3_MANAGED,
            removalPolicy: core_1.RemovalPolicy.DESTROY,
            autoDeleteObjects: true,
            serverAccessLogsBucket: this.defsAccessLogsBucket,
            serverAccessLogsPrefix: logs_bucket === false ? undefined : logs_bucket_prefix,
            blockPublicAccess: {
                blockPublicAcls: true,
                blockPublicPolicy: true,
                ignorePublicAcls: true,
                restrictPublicBuckets: true,
            },
        });
        defs_bucket.addToResourcePolicy(new aws_iam_1.PolicyStatement({
            effect: aws_iam_1.Effect.DENY,
            actions: ['s3:*'],
            resources: [defs_bucket.arnForObjects('*'), defs_bucket.bucketArn],
            principals: [new aws_iam_1.AnyPrincipal()],
            conditions: {
                Bool: {
                    'aws:SecureTransport': false,
                },
            },
        }));
        defs_bucket.addToResourcePolicy(new aws_iam_1.PolicyStatement({
            effect: aws_iam_1.Effect.ALLOW,
            actions: ['s3:GetObject', 's3:ListBucket'],
            resources: [defs_bucket.arnForObjects('*'), defs_bucket.bucketArn],
            principals: [new aws_iam_1.AnyPrincipal()],
            conditions: {
                StringEquals: {
                    'aws:SourceVpce': this._s3Gw.vpcEndpointId,
                },
            },
        }));
        defs_bucket.addToResourcePolicy(new aws_iam_1.PolicyStatement({
            effect: aws_iam_1.Effect.DENY,
            actions: ['s3:PutBucketPolicy', 's3:DeleteBucketPolicy'],
            resources: [defs_bucket.bucketArn],
            notPrincipals: [new aws_iam_1.AccountRootPrincipal()],
        }));
        this._s3Gw.addToPolicy(new aws_iam_1.PolicyStatement({
            effect: aws_iam_1.Effect.ALLOW,
            actions: ['s3:GetObject', 's3:ListBucket'],
            resources: [defs_bucket.arnForObjects('*'), defs_bucket.bucketArn],
            principals: [new aws_iam_1.AnyPrincipal()],
        }));
        this._scanFunction = new aws_lambda_1.DockerImageFunction(this, 'ServerlessClamscan', {
            code: aws_lambda_1.DockerImageCode.fromImageAsset(path.join(__dirname, '../assets/lambda/code/scan'), {
                buildArgs: {
                    // Only force update the docker layer cache once a day
                    CACHE_DATE: new Date().toDateString(),
                },
                extraHash: Date.now().toString(),
            }),
            onSuccess: this.resultDest,
            onFailure: this.errorDest,
            filesystem: aws_lambda_1.FileSystem.fromEfsAccessPoint(lambda_ap, this._efsMountPath),
            vpc: vpc,
            vpcSubnets: { subnets: vpc.isolatedSubnets },
            allowAllOutbound: false,
            timeout: core_1.Duration.minutes(15),
            memorySize: 10240,
            reservedConcurrentExecutions: props.reservedConcurrency,
            environment: {
                EFS_MOUNT_PATH: this._efsMountPath,
                EFS_DEF_PATH: this._efsDefsPath,
                DEFS_URL: defs_bucket.virtualHostedUrlForObject(),
                POWERTOOLS_METRICS_NAMESPACE: 'serverless-clamscan',
                POWERTOOLS_SERVICE_NAME: 'virus-scan',
            },
        });
        if (this._scanFunction.role) {
            cdk_nag_1.NagSuppressions.addResourceSuppressions(this._scanFunction.role, [
                {
                    id: 'AwsSolutions-IAM4',
                    reason: 'The AWSLambdaBasicExecutionRole does not provide permissions beyond uploading logs to CloudWatch. The AWSLambdaVPCAccessExecutionRole is required for functions with VPC access to manage elastic network interfaces.',
                },
            ]);
            cdk_nag_1.NagSuppressions.addResourceSuppressions(this._scanFunction.role, [
                {
                    id: 'AwsSolutions-IAM5',
                    reason: 'The EFS mount point permissions are controlled through a condition which limit the scope of the * resources.',
                },
            ], true);
        }
        this._scanFunction.connections.allowToAnyIpv4(aws_ec2_1.Port.tcp(443), 'Allow outbound HTTPS traffic for S3 access.');
        defs_bucket.grantRead(this._scanFunction);
        const download_defs = new aws_lambda_1.DockerImageFunction(this, 'DownloadDefs', {
            code: aws_lambda_1.DockerImageCode.fromImageAsset(path.join(__dirname, '../assets/lambda/code/download_defs'), {
                buildArgs: {
                    // Only force update the docker layer cache once a day
                    CACHE_DATE: new Date().toDateString(),
                },
                extraHash: Date.now().toString(),
            }),
            timeout: core_1.Duration.minutes(5),
            memorySize: 1024,
            environment: {
                DEFS_BUCKET: defs_bucket.bucketName,
                POWERTOOLS_SERVICE_NAME: 'freshclam-update',
            },
        });
        const stack = core_1.Stack.of(this);
        if (download_defs.role) {
            const download_defs_role = `arn:${stack.partition}:sts::${stack.account}:assumed-role/${download_defs.role.roleName}/${download_defs.functionName}`;
            const download_defs_assumed_principal = new aws_iam_1.ArnPrincipal(download_defs_role);
            defs_bucket.addToResourcePolicy(new aws_iam_1.PolicyStatement({
                effect: aws_iam_1.Effect.DENY,
                actions: ['s3:PutObject*'],
                resources: [defs_bucket.arnForObjects('*')],
                notPrincipals: [download_defs.role, download_defs_assumed_principal],
            }));
            defs_bucket.grantReadWrite(download_defs);
            cdk_nag_1.NagSuppressions.addResourceSuppressions(download_defs.role, [
                {
                    id: 'AwsSolutions-IAM4',
                    reason: 'The AWSLambdaBasicExecutionRole does not provide permissions beyond uploading logs to CloudWatch.',
                },
            ]);
            cdk_nag_1.NagSuppressions.addResourceSuppressions(download_defs.role, [
                {
                    id: 'AwsSolutions-IAM5',
                    reason: 'The function is allowed to invoke the download defs Lambda function.',
                },
            ], true);
        }
        new aws_events_1.Rule(this, 'VirusDefsUpdateRule', {
            schedule: aws_events_1.Schedule.rate(core_1.Duration.hours(12)),
            targets: [new aws_events_targets_1.LambdaFunction(download_defs)],
        });
        const init_defs_cr = new aws_lambda_1.Function(this, 'InitDefs', {
            runtime: aws_lambda_1.Runtime.PYTHON_3_8,
            code: aws_lambda_1.Code.fromAsset(path.join(__dirname, '../assets/lambda/code/initialize_defs_cr')),
            handler: 'lambda.lambda_handler',
            timeout: core_1.Duration.minutes(5),
        });
        download_defs.grantInvoke(init_defs_cr);
        if (init_defs_cr.role) {
            cdk_nag_1.NagSuppressions.addResourceSuppressions(init_defs_cr.role, [
                {
                    id: 'AwsSolutions-IAM4',
                    reason: 'The AWSLambdaBasicExecutionRole does not provide permissions beyond uploading logs to CloudWatch.',
                },
                {
                    id: 'AwsSolutions-IAM5',
                    reason: 'The AWSLambdaBasicExecutionRole does not provide permissions beyond uploading logs to CloudWatch.',
                },
            ], true);
        }
        new core_1.CustomResource(this, 'InitDefsCr', {
            serviceToken: init_defs_cr.functionArn,
            properties: {
                FnName: download_defs.functionName,
            },
        });
        if (props.buckets) {
            props.buckets.forEach((bucket) => {
                this.addSourceBucket(bucket);
            });
        }
    }
    /**
     * Sets the specified S3 Bucket as a s3:ObjectCreate* for the ClamAV function.
       Grants the ClamAV function permissions to get and tag objects.
       Adds a bucket policy to disallow GetObject operations on files that are tagged 'IN PROGRESS', 'INFECTED', or 'ERROR'.
     * @param bucket The bucket to add the scanning bucket policy and s3:ObjectCreate* trigger to.
     */
    addSourceBucket(bucket) {
        this._scanFunction.addEventSource(new aws_lambda_event_sources_1.S3EventSource(bucket, { events: [aws_s3_1.EventType.OBJECT_CREATED] }));
        bucket.grantRead(this._scanFunction);
        this._scanFunction.addToRolePolicy(new aws_iam_1.PolicyStatement({
            effect: aws_iam_1.Effect.ALLOW,
            actions: ['s3:PutObjectTagging', 's3:PutObjectVersionTagging'],
            resources: [bucket.arnForObjects('*')],
        }));
        if (this._scanFunction.role) {
            const stack = core_1.Stack.of(this);
            const scan_assumed_role = `arn:${stack.partition}:sts::${stack.account}:assumed-role/${this._scanFunction.role.roleName}/${this._scanFunction.functionName}`;
            const scan_assumed_principal = new aws_iam_1.ArnPrincipal(scan_assumed_role);
            this._s3Gw.addToPolicy(new aws_iam_1.PolicyStatement({
                effect: aws_iam_1.Effect.ALLOW,
                actions: ['s3:GetObject*', 's3:GetBucket*', 's3:List*'],
                resources: [bucket.bucketArn, bucket.arnForObjects('*')],
                principals: [this._scanFunction.role, scan_assumed_principal],
            }));
            this._s3Gw.addToPolicy(new aws_iam_1.PolicyStatement({
                effect: aws_iam_1.Effect.ALLOW,
                actions: ['s3:PutObjectTagging', 's3:PutObjectVersionTagging'],
                resources: [bucket.arnForObjects('*')],
                principals: [this._scanFunction.role, scan_assumed_principal],
            }));
            // Need the assumed role for the not Principal Action with Lambda
            bucket.addToResourcePolicy(new aws_iam_1.PolicyStatement({
                effect: aws_iam_1.Effect.DENY,
                actions: ['s3:GetObject'],
                resources: [bucket.arnForObjects('*')],
                notPrincipals: [this._scanFunction.role, scan_assumed_principal],
                conditions: {
                    StringEquals: {
                        's3:ExistingObjectTag/scan-status': [
                            'IN PROGRESS',
                            'INFECTED',
                            'ERROR',
                        ],
                    },
                },
            }));
        }
    }
}
exports.ServerlessClamscan = ServerlessClamscan;
_a = JSII_RTTI_SYMBOL_1;
ServerlessClamscan[_a] = { fqn: "cdk-serverless-clamscan.ServerlessClamscan", version: "0.0.0" };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSxxRUFBcUU7QUFDckUsc0NBQXNDO0FBRXRDLDZCQUE2QjtBQUM3Qiw4Q0FPMEI7QUFDMUIsOENBQWdGO0FBQ2hGLG9EQUErRDtBQUMvRCxvRUFBNkQ7QUFDN0QsOENBTTBCO0FBQzFCLG9EQVE2QjtBQUM3Qiw4RUFHMEM7QUFDMUMsZ0ZBQWtFO0FBQ2xFLDRDQUErRTtBQUMvRSw4Q0FBMEQ7QUFDMUQsd0NBTXVCO0FBQ3ZCLHFDQUEwQztBQThDMUM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztHQWlDRztBQUNILE1BQWEsa0JBQW1CLFNBQVEsZ0JBQVM7SUErQy9DOzs7OztPQUtHO0lBQ0gsWUFBWSxLQUFnQixFQUFFLEVBQVUsRUFBRSxLQUE4Qjs7UUFDdEUsS0FBSyxDQUFDLEtBQUssRUFBRSxFQUFFLENBQUMsQ0FBQztRQVhYLGlCQUFZLEdBQUcsU0FBUyxDQUFDO1FBQ3pCLGtCQUFhLEdBQUcsT0FBTyxJQUFJLENBQUMsWUFBWSxFQUFFLENBQUM7UUFDM0MsaUJBQVksR0FBRyxpQkFBaUIsQ0FBQztRQVd2QyxJQUFJLENBQUMsS0FBSyxDQUFDLFFBQVEsRUFBRTtZQUNuQixJQUFJLENBQUMsU0FBUyxHQUFHLElBQUkscUJBQVEsQ0FBQyxJQUFJLEVBQUUsZUFBZSxDQUFDLENBQUM7WUFDckQsSUFBSSxDQUFDLFVBQVUsR0FBRyxJQUFJLGdEQUFzQixDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsQ0FBQztZQUM3RCxJQUFJLENBQUMsWUFBWSxHQUFHLElBQUksaUJBQUksQ0FBQyxJQUFJLEVBQUUsY0FBYyxFQUFFO2dCQUNqRCxRQUFRLEVBQUUsSUFBSSxDQUFDLFNBQVM7Z0JBQ3hCLFdBQVcsRUFBRSwwQ0FBMEM7Z0JBQ3ZELFlBQVksRUFBRTtvQkFDWixNQUFNLEVBQUU7d0JBQ04sZUFB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QU0sRUFBRSxnQkFBTSxDQUFDLElBQUk7Z0JBQ25CLE9BQU8sRUFBRSxDQUFDLGNBQWMsQ0FBQztnQkFDekIsU0FBUyxFQUFFLENBQUMsTUFBTSxDQUFDLGFBQWEsQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFDdEMsYUFBYSxFQUFFLENBQUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLEVBQUUsc0JBQXNCLENBQUM7Z0JBQ2hFLFVBQVUsRUFBRTtvQkFDVixZQUFZLEVBQUU7d0JBQ1osa0NBQWtDLEVBQUU7NEJBQ2xDLGFBQWE7NEJBQ2IsVUFBVTs0QkFDVixPQUFPO3lCQUNSO3FCQUNGO2lCQUNGO2FBQ0YsQ0FBQyxDQUNILENBQUM7U0FDSDtJQUNILENBQUM7O0FBNWRILGdEQTZkQyIsInNvdXJjZXNDb250ZW50IjpbIi8vIENvcHlyaWdodCBBbWF6b24uY29tLCBJbmMuIG9yIGl0cyBhZmZpbGlhdGVzLiBBbGwgUmlnaHRzIFJlc2VydmVkLlxuLy8gU1BEWC1MaWNlbnNlLUlkZW50aWZpZXI6IEFwYWNoZS0yLjBcblxuaW1wb3J0ICogYXMgcGF0aCBmcm9tICdwYXRoJztcbmltcG9ydCB7XG4gIFZwYyxcbiAgU3VibmV0VHlwZSxcbiAgR2F0ZXdheVZwY0VuZHBvaW50LFxuICBHYXRld2F5VnBjRW5kcG9pbnRBd3NTZXJ2aWNlLFxuICBQb3J0LFxuICBTZWN1cml0eUdyb3VwLFxufSBmcm9tICdAYXdzLWNkay9hd3MtZWMyJztcbmltcG9ydCB7IEZpbGVTeXN0ZW0sIExpZmVjeWNsZVBvbGljeSwgUGVyZm9ybWFuY2VNb2RlIH0gZnJvbSAnQGF3cy1jZGsvYXdzLWVmcyc7XG5pbXBvcnQgeyBFdmVudEJ1cywgUnVsZSwgU2NoZWR1bGUgfSBmcm9tICdAYXdzLWNkay9hd3MtZXZlbnRzJztcbmltcG9ydCB7IExhbWJkYUZ1bmN0aW9uIH0gZnJvbSAnQGF3cy1jZGsvYXdzLWV2ZW50cy10YXJnZXRzJztcbmltcG9ydCB7XG4gIEVmZmVjdCxcbiAgUG9saWN5U3RhdGVtZW50LFxuICBBcm5QcmluY2lwYWwsXG4gIEFueVByaW5jaXBhbCxcbiAgQWNjb3VudFJvb3RQcmluY2lwYWwsXG59IGZyb20gJ0Bhd3MtY2RrL2F3cy1pYW0nO1xuaW1wb3J0IHtcbiAgRG9ja2VySW1hZ2VDb2RlLFxuICBEb2NrZXJJbWFnZUZ1bmN0aW9uLFxuICBGdW5jdGlvbixcbiAgSURlc3RpbmF0aW9uLFxuICBGaWxlU3lzdGVtIGFzIExhbWJkYUZpbGVTeXN0ZW0sXG4gIFJ1bnRpbWUsXG4gIENvZGUsXG59IGZyb20gJ0Bhd3MtY2RrL2F3cy1sYW1iZGEnO1xuaW1wb3J0IHtcbiAgRXZlbnRCcmlkZ2VEZXN0aW5hdGlvbixcbiAgU3FzRGVzdGluYXRpb24sXG59IGZyb20gJ0Bhd3MtY2RrL2F3cy1sYW1iZGEtZGVzdGluYXRpb25zJztcbmltcG9ydCB7IFMzRXZlbnRTb3VyY2UgfSBmcm9tICdAYXdzLWNkay9hd3MtbGFtYmRhLWV2ZW50LXNvdXJjZXMnO1xuaW1wb3J0IHsgSUJ1Y2tldCwgQnVja2V0LCBCdWNrZXRFbmNyeXB0aW9uLCBFdmVudFR5cGUgfSBmcm9tICdAYXdzLWNkay9hd3MtczMnO1xuaW1wb3J0IHsgUXVldWUsIFF1ZXVlRW5jcnlwdGlvbiB9IGZyb20gJ0Bhd3MtY2RrL2F3cy1zcXMnO1xuaW1wb3J0IHtcbiAgQ29uc3RydWN0LFxuICBEdXJhdGlvbixcbiAgQ3VzdG9tUmVzb3VyY2UsXG4gIFJlbW92YWxQb2xpY3ksXG4gIFN0YWNrLFxufSBmcm9tICdAYXdzLWNkay9jb3JlJztcbmltcG9ydCB7IE5hZ1N1cHByZXNzaW9ucyB9IGZyb20gJ2Nkay1uYWcnO1xuLyoqXG4gKiBJbnRlcmZhY2UgZm9yIFNlcnZlcmxlc3NDbGFtc2NhbiBWaXJ1cyBEZWZpbml0aW9ucyBTMyBCdWNrZXQgTG9nZ2luZy5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBTZXJ2ZXJsZXNzQ2xhbXNjYW5Mb2dnaW5nUHJvcHMge1xuICAvKipcbiAgICogRGVzdGluYXRpb24gYnVja2V0IGZvciB0aGUgc2VydmVyIGFjY2VzcyBsb2dzIChEZWZhdWx0OiBDcmVhdGVzIGEgbmV3IFMzIEJ1Y2tldCBmb3IgYWNjZXNzIGxvZ3MgKS5cbiAgICovXG4gIHJlYWRvbmx5IGxvZ3NCdWNrZXQ/OiBib29sZWFuIHwgSUJ1Y2tldDtcbiAgLyoqXG4gICAqIE9wdGlvbmFsIGxvZyBmaWxlIHByZWZpeCB0byB1c2UgZm9yIHRoZSBidWNrZXQncyBhY2Nlc3MgbG9ncywgb3B0aW9uIGlzIGlnbm9yZWQgaWYgbG9nc19idWNrZXQgaXMgc2V0IHRvIGZhbHNlLlxuICAgKi9cbiAgcmVhZG9ubHkgbG9nc1ByZWZpeD86IHN0cmluZztcbn1cblxuLyoqXG4gKiBJbnRlcmZhY2UgZm9yIGNyZWF0aW5nIGEgU2VydmVybGVzc0NsYW1zY2FuLlxuICovXG5leHBvcnQgaW50ZXJmYWNlIFNlcnZlcmxlc3NDbGFtc2NhblByb3BzIHtcbiAgLyoqXG4gICAqIEFuIG9wdGlvbmFsIGxpc3Qgb2YgUzMgYnVja2V0cyB0byBjb25maWd1cmUgZm9yIENsYW1BViBWaXJ1cyBTY2FubmluZzsgYnVja2V0cyBjYW4gYmUgYWRkZWQgbGF0ZXIgYnkgY2FsbGluZyBhZGRTb3VyY2VCdWNrZXQuXG4gICAqL1xuICByZWFkb25seSBidWNrZXRzPzogQnVja2V0W107XG4gIC8qKlxuICAgKiBPcHRpb25hbGx5IHNldCBhIHJlc2VydmVkIGNvbmN1cnJlbmN5IGZvciB0aGUgdmlydXMgc2Nhbm5pbmcgTGFtYmRhLlxuICAgKiBAc2VlIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9sYW1iZGEvbGF0ZXN0L29wZXJhdG9yZ3VpZGUvcmVzZXJ2ZWQtY29uY3VycmVuY3kuaHRtbFxuICAgKi9cbiAgcmVhZG9ubHkgcmVzZXJ2ZWRDb25jdXJyZW5jeT86IG51bWJlcjtcbiAgLyoqXG4gICAqIFRoZSBMYW1iZGEgRGVzdGluYXRpb24gZm9yIGZpbGVzIG1hcmtlZCAnQ0xFQU4nIG9yICdJTkZFQ1RFRCcgYmFzZWQgb24gdGhlIENsYW1BViBWaXJ1cyBzY2FuIG9yICdOL0EnIGZvciBzY2FucyB0cmlnZ2VyZWQgYnkgUzMgZm9sZGVyIGNyZWF0aW9uIGV2ZW50cyBtYXJrZWQgKERlZmF1bHQ6IENyZWF0ZXMgYW5kIHB1Ymxpc2hlcyB0byBhIG5ldyBFdmVudCBCcmlkZ2UgQnVzIGlmIHVuc3BlY2lmaWVkKS5cbiAgICovXG4gIHJlYWRvbmx5IG9uUmVzdWx0PzogSURlc3RpbmF0aW9uO1xuICAvKipcbiAgICogVGhlIExhbWJkYSBEZXN0aW5hdGlvbiBmb3IgZmlsZXMgdGhhdCBmYWlsIHRvIHNjYW4gYW5kIGFyZSBtYXJrZWQgJ0VSUk9SJyBvciBzdHVjayAnSU4gUFJPR1JFU1MnIGR1ZSB0byBhIExhbWJkYSB0aW1lb3V0IChEZWZhdWx0OiBDcmVhdGVzIGFuZCBwdWJsaXNoZXMgdG8gYSBuZXcgU1FTIHF1ZXVlIGlmIHVuc3BlY2lmaWVkKS5cbiAgICovXG4gIHJlYWRvbmx5IG9uRXJyb3I/OiBJRGVzdGluYXRpb247XG4gIC8qKlxuICAgKiBXaGV0aGVyIG9yIG5vdCB0byBlbmFibGUgZW5jcnlwdGlvbiBvbiBFRlMgZmlsZXN5c3RlbSAoRGVmYXVsdDogZW5hYmxlZCkuXG4gICAqL1xuICByZWFkb25seSBlZnNFbmNyeXB0aW9uPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIFdoZXRoZXIgb3Igbm90IHRvIGVuYWJsZSBBY2Nlc3MgTG9nZ2luZyBmb3IgdGhlIFZpcnVzIERlZmluaXRpb25zIGJ1Y2tldCwgeW91IGNhbiBzcGVjaWZ5IGFuIGV4aXN0aW5nIGJ1Y2tldCBhbmQgcHJlZml4IChEZWZhdWx0OiBDcmVhdGVzIGEgbmV3IFMzIEJ1Y2tldCBmb3IgYWNjZXNzIGxvZ3MgKS5cbiAgICovXG4gIHJlYWRvbmx5IGRlZnNCdWNrZXRBY2Nlc3NMb2dzQ29uZmlnPzogU2VydmVybGVzc0NsYW1zY2FuTG9nZ2luZ1Byb3BzO1xufVxuXG4vKipcbiAgQW4gW2F3cy1jZGtdKGh0dHBzOi8vZ2l0aHViLmNvbS9hd3MvYXdzLWNkaykgY29uc3RydWN0IHRoYXQgdXNlcyBbQ2xhbUFWwq5dKGh0dHBzOi8vd3d3LmNsYW1hdi5uZXQvKS5cbiAgdG8gc2NhbiBvYmplY3RzIGluIEFtYXpvbiBTMyBmb3IgdmlydXNlcy4gVGhlIGNvbnN0cnVjdCBwcm92aWRlcyBhIGZsZXhpYmxlIGludGVyZmFjZSBmb3IgYSBzeXN0ZW1cbiAgdG8gYWN0IGJhc2VkIG9uIHRoZSByZXN1bHRzIG9mIGEgQ2xhbUFWIHZpcnVzIHNjYW4uXG5cbiAgVGhlIGNvbnN0cnVjdCBjcmVhdGVzIGEgTGFtYmRhIGZ1bmN0aW9uIHdpdGggRUZTIGludGVncmF0aW9uIHRvIHN1cHBvcnQgbGFyZ2VyIGZpbGVzLlxuICBBIFZQQyB3aXRoIGlzb2xhdGVkIHN1Ym5ldHMsIGEgUzMgR2F0ZXdheSBlbmRwb2ludCB3aWxsIGFsc28gYmUgY3JlYXRlZC5cblxuICBBZGRpdGlvbmFsbHkgY3JlYXRlcyBhbiB0d2ljZS1kYWlseSBqb2IgdG8gZG93bmxvYWQgdGhlIGxhdGVzdCBDbGFtQVYgZGVmaW5pdGlvbiBmaWxlcyB0byB0aGVcbiAgVmlydXMgRGVmaW5pdGlvbnMgUzMgQnVja2V0IGJ5IHV0aWxpemluZyBhbiBFdmVudEJyaWRnZSBydWxlIGFuZCBhIExhbWJkYSBmdW5jdGlvbiBhbmRcbiAgcHVibGlzaGVzIENsb3VkV2F0Y2ggTWV0cmljcyB0byB0aGUgJ3NlcnZlcmxlc3MtY2xhbXNjYW4nIG5hbWVzcGFjZS5cblxuICBfX0ltcG9ydGFudCBPJk1fXzpcbiAgV2hlbiBDbGFtQVYgcHVibGlzaGVzIHVwZGF0ZXMgdG8gdGhlIHNjYW5uZXIgeW91IHdpbGwgc2VlIOKAnFlvdXIgQ2xhbUFWIGluc3RhbGxhdGlvbiBpcyBPVVREQVRFROKAnSBpbiB5b3VyIHNjYW4gcmVzdWx0cy5cbiAgV2hpbGUgdGhlIGNvbnN0cnVjdCBjcmVhdGVzIGEgc3lzdGVtIHRvIGtlZXAgdGhlIGRhdGFiYXNlIGRlZmluaXRpb25zIHVwIHRvIGRhdGUsIHlvdSBtdXN0IHVwZGF0ZSB0aGUgc2Nhbm5lciB0b1xuICBkZXRlY3QgYWxsIHRoZSBsYXRlc3QgVmlydXNlcy5cblxuICBVcGRhdGUgdGhlIGRvY2tlciBpbWFnZXMgb2YgdGhlIExhbWJkYSBmdW5jdGlvbnMgd2l0aCB0aGUgbGF0ZXN0IHZlcnNpb24gb2YgQ2xhbUFWIGJ5IHJlLXJ1bm5pbmcgYGNkayBkZXBsb3lgLlxuXG4gIFN1Y2Nlc3NmdWwgU2NhbiBFdmVudCBmb3JtYXRcbiAgYGBganNvblxuICB7XG4gICAgIFwic291cmNlXCI6IFwic2VydmVybGVzcy1jbGFtc2NhblwiLFxuICAgICBcImlucHV0X2J1Y2tldFwiOiA8aW5wdXRfYnVja2V0X25hbWU+LFxuICAgICBcImlucHV0X2tleVwiOiA8b2JqZWN0X2tleT4sXG4gICAgIFwic3RhdHVzXCI6IDxcIkNMRUFOXCJ8XCJJTkZFQ1RFRFwifFwiTi9BXCI+LFxuICAgICBcIm1lc3NhZ2VcIjogPHNjYW5fc3VtbWFyeT4sXG4gICB9XG4gIGBgYFxuXG4gIE5vdGU6IFRoZSBWaXJ1cyBEZWZpbml0aW9ucyBidWNrZXQgcG9saWN5IHdpbGwgbGlrZWx5IGNhdXNlIGEgZGVsZXRpb24gZXJyb3IgaWYgeW91IGNob29zZSB0byBkZWxldGVcbiAgdGhlIHN0YWNrIGFzc29jaWF0ZWQgaW4gdGhlIGNvbnN0cnVjdC4gSG93ZXZlciBzaW5jZSB0aGUgYnVja2V0IGl0c2VsZiBnZXRzIGRlbGV0ZWQsIHlvdSBjYW4gZGVsZXRlXG4gIHRoZSBzdGFjayBhZ2FpbiB0byByZXNvbHZlIHRoZSBlcnJvci5cbiAqL1xuZXhwb3J0IGNsYXNzIFNlcnZlcmxlc3NDbGFtc2NhbiBleHRlbmRzIENvbnN0cnVjdCB7XG4gIC8qKlxuICAgIFRoZSBMYW1iZGEgRGVzdGluYXRpb24gZm9yIGZhaWxlZCBvbiBlcnJlZCBzY2FucyBbRVJST1IsIElOIFBST0dSRVNTIChJZiBlcnJvciBpcyBkdWUgdG8gTGFtYmRhIHRpbWVvdXQpXS5cbiAgICovXG4gIHB1YmxpYyByZWFkb25seSBlcnJvckRlc3Q6IElEZXN0aW5hdGlvbjtcblxuICAvKipcbiAgICBUaGUgTGFtYmRhIERlc3RpbmF0aW9uIGZvciBjb21wbGV0ZWQgQ2xhbUFWIHNjYW5zIFtDTEVBTiwgSU5GRUNURURdLlxuICAgKi9cbiAgcHVibGljIHJlYWRvbmx5IHJlc3VsdERlc3Q6IElEZXN0aW5hdGlvbjtcblxuICAvKipcbiAgICBDb25kaXRpb25hbDogVGhlIFNRUyBRdWV1ZSBmb3IgZXJyZWQgc2NhbnMgaWYgYSBmYWlsdXJlIChvbkVycm9yKSBkZXN0aW5hdGlvbiB3YXMgbm90IHNwZWNpZmllZC5cbiAgICovXG4gIHB1YmxpYyByZWFkb25seSBlcnJvclF1ZXVlPzogUXVldWU7XG5cbiAgLyoqXG4gICAgQ29uZGl0aW9uYWw6IFRoZSBTUVMgRGVhZCBMZXR0ZXIgUXVldWUgZm9yIHRoZSBlcnJvclF1ZXVlIGlmIGEgZmFpbHVyZSAob25FcnJvcikgZGVzdGluYXRpb24gd2FzIG5vdCBzcGVjaWZpZWQuXG4gICAqL1xuICBwdWJsaWMgcmVhZG9ubHkgZXJyb3JEZWFkTGV0dGVyUXVldWU/OiBRdWV1ZTtcblxuICAvKipcbiAgICBDb25kaXRpb25hbDogVGhlIEV2ZW50IEJyaWRnZSBCdXMgZm9yIGNvbXBsZXRlZCBDbGFtQVYgc2NhbnMgaWYgYSBzdWNjZXNzIChvblJlc3VsdCkgZGVzdGluYXRpb24gd2FzIG5vdCBzcGVjaWZpZWQuXG4gICAqL1xuICBwdWJsaWMgcmVhZG9ubHkgcmVzdWx0QnVzPzogRXZlbnRCdXM7XG5cbiAgLyoqXG4gICAgQ29uZGl0aW9uYWw6IEFuIEV2ZW50IEJyaWRnZSBSdWxlIGZvciBmaWxlcyB0aGF0IGFyZSBtYXJrZWQgJ0NMRUFOJyBieSBDbGFtQVYgaWYgYSBzdWNjZXNzIGRlc3RpbmF0aW9uIHdhcyBub3Qgc3BlY2lmaWVkLlxuICAgKi9cbiAgcHVibGljIHJlYWRvbmx5IGNsZWFuUnVsZT86IFJ1bGU7XG5cbiAgLyoqXG4gICAgQ29uZGl0aW9uYWw6IEFuIEV2ZW50IEJyaWRnZSBSdWxlIGZvciBmaWxlcyB0aGF0IGFyZSBtYXJrZWQgJ0lORkVDVEVEJyBieSBDbGFtQVYgaWYgYSBzdWNjZXNzIGRlc3RpbmF0aW9uIHdhcyBub3Qgc3BlY2lmaWVkLlxuICAgKi9cbiAgcHVibGljIHJlYWRvbmx5IGluZmVjdGVkUnVsZT86IFJ1bGU7XG5cbiAgLyoqXG4gICAgQ29uZGl0aW9uYWw6IFRoZSBCdWNrZXQgZm9yIGFjY2VzcyBsb2dzIGZvciB0aGUgdmlydXMgZGVmaW5pdGlvbnMgYnVja2V0IGlmIGxvZ2dpbmcgaXMgZW5hYmxlZCAoZGVmc0J1Y2tldEFjY2Vzc0xvZ3NDb25maWcpLlxuICAgKi9cbiAgcHVibGljIHJlYWRvbmx5IGRlZnNBY2Nlc3NMb2dzQnVja2V0PzogSUJ1Y2tldDtcblxuICBwcml2YXRlIF9zY2FuRnVuY3Rpb246IERvY2tlckltYWdlRnVuY3Rpb247XG4gIHByaXZhdGUgX3MzR3c6IEdhdGV3YXlWcGNFbmRwb2ludDtcbiAgcHJpdmF0ZSBfZWZzUm9vdFBhdGggPSAnL2xhbWJkYSc7XG4gIHByaXZhdGUgX2Vmc01vdW50UGF0aCA9IGAvbW50JHt0aGlzLl9lZnNSb290UGF0aH1gO1xuICBwcml2YXRlIF9lZnNEZWZzUGF0aCA9ICd2aXJ1c19kYXRhYmFzZS8nO1xuXG4gIC8qKlxuICAgKiBDcmVhdGVzIGEgU2VydmVybGVzc0NsYW1zY2FuIGNvbnN0cnVjdC5cbiAgICogQHBhcmFtIHNjb3BlIFRoZSBwYXJlbnQgY3JlYXRpbmcgY29uc3RydWN0ICh1c3VhbGx5IGB0aGlzYCkuXG4gICAqIEBwYXJhbSBpZCBUaGUgY29uc3RydWN0J3MgbmFtZS5cbiAgICogQHBhcmFtIHByb3BzIEEgYFNlcnZlcmxlc3NDbGFtc2NhblByb3BzYCBpbnRlcmZhY2UuXG4gICAqL1xuICBjb25zdHJ1Y3RvcihzY29wZTogQ29uc3RydWN0LCBpZDogc3RyaW5nLCBwcm9wczogU2VydmVybGVzc0NsYW1zY2FuUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQpO1xuXG4gICAgaWYgKCFwcm9wcy5vblJlc3VsdCkge1xuICAgICAgdGhpcy5yZXN1bHRCdXMgPSBuZXcgRXZlbnRCdXModGhpcywgJ1NjYW5SZXN1bHRCdXMnKTtcbiAgICAgIHRoaXMucmVzdWx0RGVzdCA9IG5ldyBFdmVudEJyaWRnZURlc3RpbmF0aW9uKHRoaXMucmVzdWx0QnVzKTtcbiAgICAgIHRoaXMuaW5mZWN0ZWRSdWxlID0gbmV3IFJ1bGUodGhpcywgJ0luZmVjdGVkUnVsZScsIHtcbiAgICAgICAgZXZlbnRCdXM6IHRoaXMucmVzdWx0QnVzLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ0V2ZW50IGZvciB3aGVuIGEgZmlsZSBpcyBtYXJrZWQgSU5GRUNURUQnLFxuICAgICAgICBldmVudFBhdHRlcm46IHtcbiAgICAgICAgICBkZXRhaWw6IHtcbiAgICAgICAgICAgIHJlc3BvbnNlUGF5bG9hZDoge1xuICAgICAgICAgICAgICBzb3VyY2U6IFsnc2VydmVybGVzcy1jbGFtc2NhbiddLFxuICAgICAgICAgICAgICBzdGF0dXM6IFsnSU5GRUNURUQnXSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgICAgdGhpcy5jbGVhblJ1bGUgPSBuZXcgUnVsZSh0aGlzLCAnQ2xlYW5SdWxlJywge1xuICAgICAgICBldmVudEJ1czogdGhpcy5yZXN1bHRCdXMsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRXZlbnQgZm9yIHdoZW4gYSBmaWxlIGlzIG1hcmtlZCBDTEVBTicsXG4gICAgICAgIGV2ZW50UGF0dGVybjoge1xuICAgICAgICAgIGRldGFpbDoge1xuICAgICAgICAgICAgcmVzcG9uc2VQYXlsb2FkOiB7XG4gICAgICAgICAgICAgIHNvdXJjZTogWydzZXJ2ZXJsZXNzLWNsYW1zY2FuJ10sXG4gICAgICAgICAgICAgIHN0YXR1czogWydDTEVBTiddLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMucmVzdWx0RGVzdCA9IHByb3BzLm9uUmVzdWx0O1xuICAgIH1cblxuICAgIGlmICghcHJvcHMub25FcnJvcikge1xuICAgICAgdGhpcy5lcnJvckRlYWRMZXR0ZXJRdWV1ZSA9IG5ldyBRdWV1ZSh0aGlzLCAnU2NhbkVycm9yRGVhZExldHRlclF1ZXVlJywge1xuICAgICAgICBlbmNyeXB0aW9uOiBRdWV1ZUVuY3J5cHRpb24uS01TX01BTkFHRUQsXG4gICAgICB9KTtcbiAgICAgIHRoaXMuZXJyb3JEZWFkTGV0dGVyUXVldWUuYWRkVG9SZXNvdXJjZVBvbGljeShcbiAgICAgICAgbmV3IFBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgICAgYWN0aW9uczogWydzcXM6KiddLFxuICAgICAgICAgIGVmZmVjdDogRWZmZWN0LkRFTlksXG4gICAgICAgICAgcHJpbmNpcGFsczogW25ldyBBbnlQcmluY2lwYWwoKV0sXG4gICAgICAgICAgY29uZGl0aW9uczogeyBCb29sOiB7ICdhd3M6U2VjdXJlVHJhbnNwb3J0JzogZmFsc2UgfSB9LFxuICAgICAgICAgIHJlc291cmNlczogW3RoaXMuZXJyb3JEZWFkTGV0dGVyUXVldWUucXVldWVBcm5dLFxuICAgICAgICB9KSxcbiAgICAgICk7XG4gICAgICB0aGlzLmVycm9yUXVldWUgPSBuZXcgUXVldWUodGhpcywgJ1NjYW5FcnJvclF1ZXVlJywge1xuICAgICAgICBlbmNyeXB0aW9uOiBRdWV1ZUVuY3J5cHRpb24uS01TX01BTkFHRUQsXG4gICAgICAgIGRlYWRMZXR0ZXJRdWV1ZToge1xuICAgICAgICAgIG1heFJlY2VpdmVDb3VudDogMyxcbiAgICAgICAgICBxdWV1ZTogdGhpcy5lcnJvckRlYWRMZXR0ZXJRdWV1ZSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgICAgdGhpcy5lcnJvclF1ZXVlLmFkZFRvUmVzb3VyY2VQb2xpY3koXG4gICAgICAgIG5ldyBQb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgICAgIGFjdGlvbnM6IFsnc3FzOionXSxcbiAgICAgICAgICBlZmZlY3Q6IEVmZmVjdC5ERU5ZLFxuICAgICAgICAgIHByaW5jaXBhbHM6IFtuZXcgQW55UHJpbmNpcGFsKCldLFxuICAgICAgICAgIGNvbmRpdGlvbnM6IHsgQm9vbDogeyAnYXdzOlNlY3VyZVRyYW5zcG9ydCc6IGZhbHNlIH0gfSxcbiAgICAgICAgICByZXNvdXJjZXM6IFt0aGlzLmVycm9yUXVldWUucXVldWVBcm5dLFxuICAgICAgICB9KSxcbiAgICAgICk7XG4gICAgICB0aGlzLmVycm9yRGVzdCA9IG5ldyBTcXNEZXN0aW5hdGlvbih0aGlzLmVycm9yUXVldWUpO1xuICAgICAgTmFnU3VwcHJlc3Npb25zLmFkZFJlc291cmNlU3VwcHJlc3Npb25zKHRoaXMuZXJyb3JEZWFkTGV0dGVyUXVldWUsIFtcbiAgICAgICAgeyBpZDogJ0F3c1NvbHV0aW9ucy1TUVMzJywgcmVhc29uOiAnVGhpcyBxdWV1ZSBpcyBhIERMUS4nIH0sXG4gICAgICBdKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5lcnJvckRlc3QgPSBwcm9wcy5vbkVycm9yO1xuICAgIH1cblxuICAgIGNvbnN0IHZwYyA9IG5ldyBWcGModGhpcywgJ1NjYW5WUEMnLCB7XG4gICAgICBzdWJuZXRDb25maWd1cmF0aW9uOiBbXG4gICAgICAgIHtcbiAgICAgICAgICBzdWJuZXRUeXBlOiBTdWJuZXRUeXBlLlBSSVZBVEVfSVNPTEFURUQsXG4gICAgICAgICAgbmFtZTogJ0lzb2xhdGVkJyxcbiAgICAgICAgfSxcbiAgICAgIF0sXG4gICAgfSk7XG5cbiAgICB2cGMuYWRkRmxvd0xvZygnRmxvd0xvZ3MnKTtcblxuICAgIHRoaXMuX3MzR3cgPSB2cGMuYWRkR2F0ZXdheUVuZHBvaW50KCdTM0VuZHBvaW50Jywge1xuICAgICAgc2VydmljZTogR2F0ZXdheVZwY0VuZHBvaW50QXdzU2VydmljZS5TMyxcbiAgICB9KTtcblxuICAgIGNvbnN0IGZpbGVTeXN0ZW0gPSBuZXcgRmlsZVN5c3RlbSh0aGlzLCAnU2NhbkZpbGVTeXN0ZW0nLCB7XG4gICAgICB2cGM6IHZwYyxcbiAgICAgIGVuY3J5cHRlZDogcHJvcHMuZWZzRW5jcnlwdGlvbiA9PT0gZmFsc2UgPyBmYWxzZSA6IHRydWUsXG4gICAgICBsaWZlY3ljbGVQb2xpY3k6IExpZmVjeWNsZVBvbGljeS5BRlRFUl83X0RBWVMsXG4gICAgICBwZXJmb3JtYW5jZU1vZGU6IFBlcmZvcm1hbmNlTW9kZS5HRU5FUkFMX1BVUlBPU0UsXG4gICAgICByZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5LkRFU1RST1ksXG4gICAgICBzZWN1cml0eUdyb3VwOiBuZXcgU2VjdXJpdHlHcm91cCh0aGlzLCAnU2NhbkZpbGVTeXN0ZW1TZWN1cml0eUdyb3VwJywge1xuICAgICAgICB2cGM6IHZwYyxcbiAgICAgICAgYWxsb3dBbGxPdXRib3VuZDogZmFsc2UsXG4gICAgICB9KSxcbiAgICB9KTtcblxuICAgIGNvbnN0IGxhbWJkYV9hcCA9IGZpbGVTeXN0ZW0uYWRkQWNjZXNzUG9pbnQoJ1NjYW5MYW1iZGFBUCcsIHtcbiAgICAgIGNyZWF0ZUFjbDoge1xuICAgICAgICBvd25lckdpZDogJzEwMDAnLFxuICAgICAgICBvd25lclVpZDogJzEwMDAnLFxuICAgICAgICBwZXJtaXNzaW9uczogJzc1NScsXG4gICAgICB9LFxuICAgICAgcG9zaXhVc2VyOiB7XG4gICAgICAgIGdpZDogJzEwMDAnLFxuICAgICAgICB1aWQ6ICcxMDAwJyxcbiAgICAgIH0sXG4gICAgICBwYXRoOiB0aGlzLl9lZnNSb290UGF0aCxcbiAgICB9KTtcblxuICAgIGNvbnN0IGxvZ3NfYnVja2V0ID0gcHJvcHMuZGVmc0J1Y2tldEFjY2Vzc0xvZ3NDb25maWc/LmxvZ3NCdWNrZXQ7XG4gICAgY29uc3QgbG9nc19idWNrZXRfcHJlZml4ID0gcHJvcHMuZGVmc0J1Y2tldEFjY2Vzc0xvZ3NDb25maWc/LmxvZ3NQcmVmaXg7XG4gICAgaWYgKGxvZ3NfYnVja2V0ID09PSB0cnVlIHx8IGxvZ3NfYnVja2V0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgIHRoaXMuZGVmc0FjY2Vzc0xvZ3NCdWNrZXQgPSBuZXcgQnVja2V0KFxuICAgICAgICB0aGlzLFxuICAgICAgICAnVmlydXNEZWZzQWNjZXNzTG9nc0J1Y2tldCcsXG4gICAgICAgIHtcbiAgICAgICAgICBlbmNyeXB0aW9uOiBCdWNrZXRFbmNyeXB0aW9uLlMzX01BTkFHRUQsXG4gICAgICAgICAgcmVtb3ZhbFBvbGljeTogUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgICAgICAgc2VydmVyQWNjZXNzTG9nc1ByZWZpeDogJ2FjY2Vzcy1sb2dzLWJ1Y2tldC1sb2dzJyxcbiAgICAgICAgICBibG9ja1B1YmxpY0FjY2Vzczoge1xuICAgICAgICAgICAgYmxvY2tQdWJsaWNBY2xzOiB0cnVlLFxuICAgICAgICAgICAgYmxvY2tQdWJsaWNQb2xpY3k6IHRydWUsXG4gICAgICAgICAgICBpZ25vcmVQdWJsaWNBY2xzOiB0cnVlLFxuICAgICAgICAgICAgcmVzdHJpY3RQdWJsaWNCdWNrZXRzOiB0cnVlLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICApO1xuICAgICAgdGhpcy5kZWZzQWNjZXNzTG9nc0J1Y2tldC5hZGRUb1Jlc291cmNlUG9saWN5KFxuICAgICAgICBuZXcgUG9saWN5U3RhdGVtZW50KHtcbiAgICAgICAgICBlZmZlY3Q6IEVmZmVjdC5ERU5ZLFxuICAgICAgICAgIGFjdGlvbnM6IFsnczM6KiddLFxuICAgICAgICAgIHJlc291cmNlczogW1xuICAgICAgICAgICAgdGhpcy5kZWZzQWNjZXNzTG9nc0J1Y2tldC5hcm5Gb3JPYmplY3RzKCcqJyksXG4gICAgICAgICAgICB0aGlzLmRlZnNBY2Nlc3NMb2dzQnVja2V0LmJ1Y2tldEFybixcbiAgICAgICAgICBdLFxuICAgICAgICAgIHByaW5jaXBhbHM6IFtuZXcgQW55UHJpbmNpcGFsKCldLFxuICAgICAgICAgIGNvbmRpdGlvbnM6IHtcbiAgICAgICAgICAgIEJvb2w6IHtcbiAgICAgICAgICAgICAgJ2F3czpTZWN1cmVUcmFuc3BvcnQnOiBmYWxzZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSksXG4gICAgICApO1xuICAgIH0gZWxzZSBpZiAobG9nc19idWNrZXQgIT0gZmFsc2UpIHtcbiAgICAgIHRoaXMuZGVmc0FjY2Vzc0xvZ3NCdWNrZXQgPSBsb2dzX2J1Y2tldDtcbiAgICB9XG5cbiAgICBjb25zdCBkZWZzX2J1Y2tldCA9IG5ldyBCdWNrZXQodGhpcywgJ1ZpcnVzRGVmc0J1Y2tldCcsIHtcbiAgICAgIGVuY3J5cHRpb246IEJ1Y2tldEVuY3J5cHRpb24uUzNfTUFOQUdFRCxcbiAgICAgIHJlbW92YWxQb2xpY3k6IFJlbW92YWxQb2xpY3kuREVTVFJPWSxcbiAgICAgIGF1dG9EZWxldGVPYmplY3RzOiB0cnVlLFxuICAgICAgc2VydmVyQWNjZXNzTG9nc0J1Y2tldDogdGhpcy5kZWZzQWNjZXNzTG9nc0J1Y2tldCxcbiAgICAgIHNlcnZlckFjY2Vzc0xvZ3NQcmVmaXg6XG4gICAgICAgIGxvZ3NfYnVja2V0ID09PSBmYWxzZSA/IHVuZGVmaW5lZCA6IGxvZ3NfYnVja2V0X3ByZWZpeCxcbiAgICAgIGJsb2NrUHVibGljQWNjZXNzOiB7XG4gICAgICAgIGJsb2NrUHVibGljQWNsczogdHJ1ZSxcbiAgICAgICAgYmxvY2tQdWJsaWNQb2xpY3k6IHRydWUsXG4gICAgICAgIGlnbm9yZVB1YmxpY0FjbHM6IHRydWUsXG4gICAgICAgIHJlc3RyaWN0UHVibGljQnVja2V0czogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICBkZWZzX2J1Y2tldC5hZGRUb1Jlc291cmNlUG9saWN5KFxuICAgICAgbmV3IFBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgIGVmZmVjdDogRWZmZWN0LkRFTlksXG4gICAgICAgIGFjdGlvbnM6IFsnczM6KiddLFxuICAgICAgICByZXNvdXJjZXM6IFtkZWZzX2J1Y2tldC5hcm5Gb3JPYmplY3RzKCcqJyksIGRlZnNfYnVja2V0LmJ1Y2tldEFybl0sXG4gICAgICAgIHByaW5jaXBhbHM6IFtuZXcgQW55UHJpbmNpcGFsKCldLFxuICAgICAgICBjb25kaXRpb25zOiB7XG4gICAgICAgICAgQm9vbDoge1xuICAgICAgICAgICAgJ2F3czpTZWN1cmVUcmFuc3BvcnQnOiBmYWxzZSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgKTtcbiAgICBkZWZzX2J1Y2tldC5hZGRUb1Jlc291cmNlUG9saWN5KFxuICAgICAgbmV3IFBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgIGVmZmVjdDogRWZmZWN0LkFMTE9XLFxuICAgICAgICBhY3Rpb25zOiBbJ3MzOkdldE9iamVjdCcsICdzMzpMaXN0QnVja2V0J10sXG4gICAgICAgIHJlc291cmNlczogW2RlZnNfYnVja2V0LmFybkZvck9iamVjdHMoJyonKSwgZGVmc19idWNrZXQuYnVja2V0QXJuXSxcbiAgICAgICAgcHJpbmNpcGFsczogW25ldyBBbnlQcmluY2lwYWwoKV0sXG4gICAgICAgIGNvbmRpdGlvbnM6IHtcbiAgICAgICAgICBTdHJpbmdFcXVhbHM6IHtcbiAgICAgICAgICAgICdhd3M6U291cmNlVnBjZSc6IHRoaXMuX3MzR3cudnBjRW5kcG9pbnRJZCxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgKTtcbiAgICBkZWZzX2J1Y2tldC5hZGRUb1Jlc291cmNlUG9saWN5KFxuICAgICAgbmV3IFBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgIGVmZmVjdDogRWZmZWN0LkRFTlksXG4gICAgICAgIGFjdGlvbnM6IFsnczM6UHV0QnVja2V0UG9saWN5JywgJ3MzOkRlbGV0ZUJ1Y2tldFBvbGljeSddLFxuICAgICAgICByZXNvdXJjZXM6IFtkZWZzX2J1Y2tldC5idWNrZXRBcm5dLFxuICAgICAgICBub3RQcmluY2lwYWxzOiBbbmV3IEFjY291bnRSb290UHJpbmNpcGFsKCldLFxuICAgICAgfSksXG4gICAgKTtcbiAgICB0aGlzLl9zM0d3LmFkZFRvUG9saWN5KFxuICAgICAgbmV3IFBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgIGVmZmVjdDogRWZmZWN0LkFMTE9XLFxuICAgICAgICBhY3Rpb25zOiBbJ3MzOkdldE9iamVjdCcsICdzMzpMaXN0QnVja2V0J10sXG4gICAgICAgIHJlc291cmNlczogW2RlZnNfYnVja2V0LmFybkZvck9iamVjdHMoJyonKSwgZGVmc19idWNrZXQuYnVja2V0QXJuXSxcbiAgICAgICAgcHJpbmNpcGFsczogW25ldyBBbnlQcmluY2lwYWwoKV0sXG4gICAgICB9KSxcbiAgICApO1xuXG4gICAgdGhpcy5fc2NhbkZ1bmN0aW9uID0gbmV3IERvY2tlckltYWdlRnVuY3Rpb24odGhpcywgJ1NlcnZlcmxlc3NDbGFtc2NhbicsIHtcbiAgICAgIGNvZGU6IERvY2tlckltYWdlQ29kZS5mcm9tSW1hZ2VBc3NldChcbiAgICAgICAgcGF0aC5qb2luKF9fZGlybmFtZSwgJy4uL2Fzc2V0cy9sYW1iZGEvY29kZS9zY2FuJyksXG4gICAgICAgIHtcbiAgICAgICAgICBidWlsZEFyZ3M6IHtcbiAgICAgICAgICAgIC8vIE9ubHkgZm9yY2UgdXBkYXRlIHRoZSBkb2NrZXIgbGF5ZXIgY2FjaGUgb25jZSBhIGRheVxuICAgICAgICAgICAgQ0FDSEVfREFURTogbmV3IERhdGUoKS50b0RhdGVTdHJpbmcoKSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGV4dHJhSGFzaDogRGF0ZS5ub3coKS50b1N0cmluZygpLFxuICAgICAgICB9LFxuICAgICAgKSxcbiAgICAgIG9uU3VjY2VzczogdGhpcy5yZXN1bHREZXN0LFxuICAgICAgb25GYWlsdXJlOiB0aGlzLmVycm9yRGVzdCxcbiAgICAgIGZpbGVzeXN0ZW06IExhbWJkYUZpbGVTeXN0ZW0uZnJvbUVmc0FjY2Vzc1BvaW50KFxuICAgICAgICBsYW1iZGFfYXAsXG4gICAgICAgIHRoaXMuX2Vmc01vdW50UGF0aCxcbiAgICAgICksXG4gICAgICB2cGM6IHZwYyxcbiAgICAgIHZwY1N1Ym5ldHM6IHsgc3VibmV0czogdnBjLmlzb2xhdGVkU3VibmV0cyB9LFxuICAgICAgYWxsb3dBbGxPdXRib3VuZDogZmFsc2UsXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5taW51dGVzKDE1KSxcbiAgICAgIG1lbW9yeVNpemU6IDEwMjQwLFxuICAgICAgcmVzZXJ2ZWRDb25jdXJyZW50RXhlY3V0aW9uczogcHJvcHMucmVzZXJ2ZWRDb25jdXJyZW5jeSxcbiAgICAgIGVudmlyb25tZW50OiB7XG4gICAgICAgIEVGU19NT1VOVF9QQVRIOiB0aGlzLl9lZnNNb3VudFBhdGgsXG4gICAgICAgIEVGU19ERUZfUEFUSDogdGhpcy5fZWZzRGVmc1BhdGgsXG4gICAgICAgIERFRlNfVVJMOiBkZWZzX2J1Y2tldC52aXJ0dWFsSG9zdGVkVXJsRm9yT2JqZWN0KCksXG4gICAgICAgIFBPV0VSVE9PTFNfTUVUUklDU19OQU1FU1BBQ0U6ICdzZXJ2ZXJsZXNzLWNsYW1zY2FuJyxcbiAgICAgICAgUE9XRVJUT09MU19TRVJWSUNFX05BTUU6ICd2aXJ1cy1zY2FuJyxcbiAgICAgIH0sXG4gICAgfSk7XG4gICAgaWYgKHRoaXMuX3NjYW5GdW5jdGlvbi5yb2xlKSB7XG4gICAgICBOYWdTdXBwcmVzc2lvbnMuYWRkUmVzb3VyY2VTdXBwcmVzc2lvbnModGhpcy5fc2NhbkZ1bmN0aW9uLnJvbGUsIFtcbiAgICAgICAge1xuICAgICAgICAgIGlkOiAnQXdzU29sdXRpb25zLUlBTTQnLFxuICAgICAgICAgIHJlYXNvbjpcbiAgICAgICAgICAgICdUaGUgQVdTTGFtYmRhQmFzaWNFeGVjdXRpb25Sb2xlIGRvZXMgbm90IHByb3ZpZGUgcGVybWlzc2lvbnMgYmV5b25kIHVwbG9hZGluZyBsb2dzIHRvIENsb3VkV2F0Y2guIFRoZSBBV1NMYW1iZGFWUENBY2Nlc3NFeGVjdXRpb25Sb2xlIGlzIHJlcXVpcmVkIGZvciBmdW5jdGlvbnMgd2l0aCBWUEMgYWNjZXNzIHRvIG1hbmFnZSBlbGFzdGljIG5ldHdvcmsgaW50ZXJmYWNlcy4nLFxuICAgICAgICB9LFxuICAgICAgXSk7XG4gICAgICBOYWdTdXBwcmVzc2lvbnMuYWRkUmVzb3VyY2VTdXBwcmVzc2lvbnMoXG4gICAgICAgIHRoaXMuX3NjYW5GdW5jdGlvbi5yb2xlLFxuICAgICAgICBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICdBd3NTb2x1dGlvbnMtSUFNNScsXG4gICAgICAgICAgICByZWFzb246XG4gICAgICAgICAgICAgICdUaGUgRUZTIG1vdW50IHBvaW50IHBlcm1pc3Npb25zIGFyZSBjb250cm9sbGVkIHRocm91Z2ggYSBjb25kaXRpb24gd2hpY2ggbGltaXQgdGhlIHNjb3BlIG9mIHRoZSAqIHJlc291cmNlcy4nLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHRydWUsXG4gICAgICApO1xuICAgIH1cbiAgICB0aGlzLl9zY2FuRnVuY3Rpb24uY29ubmVjdGlvbnMuYWxsb3dUb0FueUlwdjQoXG4gICAgICBQb3J0LnRjcCg0NDMpLFxuICAgICAgJ0FsbG93IG91dGJvdW5kIEhUVFBTIHRyYWZmaWMgZm9yIFMzIGFjY2Vzcy4nLFxuICAgICk7XG4gICAgZGVmc19idWNrZXQuZ3JhbnRSZWFkKHRoaXMuX3NjYW5GdW5jdGlvbik7XG5cbiAgICBjb25zdCBkb3dubG9hZF9kZWZzID0gbmV3IERvY2tlckltYWdlRnVuY3Rpb24odGhpcywgJ0Rvd25sb2FkRGVmcycsIHtcbiAgICAgIGNvZGU6IERvY2tlckltYWdlQ29kZS5mcm9tSW1hZ2VBc3NldChcbiAgICAgICAgcGF0aC5qb2luKF9fZGlybmFtZSwgJy4uL2Fzc2V0cy9sYW1iZGEvY29kZS9kb3dubG9hZF9kZWZzJyksXG4gICAgICAgIHtcbiAgICAgICAgICBidWlsZEFyZ3M6IHtcbiAgICAgICAgICAgIC8vIE9ubHkgZm9yY2UgdXBkYXRlIHRoZSBkb2NrZXIgbGF5ZXIgY2FjaGUgb25jZSBhIGRheVxuICAgICAgICAgICAgQ0FDSEVfREFURTogbmV3IERhdGUoKS50b0RhdGVTdHJpbmcoKSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGV4dHJhSGFzaDogRGF0ZS5ub3coKS50b1N0cmluZygpLFxuICAgICAgICB9LFxuICAgICAgKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLm1pbnV0ZXMoNSksXG4gICAgICBtZW1vcnlTaXplOiAxMDI0LFxuICAgICAgZW52aXJvbm1lbnQ6IHtcbiAgICAgICAgREVGU19CVUNLRVQ6IGRlZnNfYnVja2V0LmJ1Y2tldE5hbWUsXG4gICAgICAgIFBPV0VSVE9PTFNfU0VSVklDRV9OQU1FOiAnZnJlc2hjbGFtLXVwZGF0ZScsXG4gICAgICB9LFxuICAgIH0pO1xuICAgIGNvbnN0IHN0YWNrID0gU3RhY2sub2YodGhpcyk7XG5cbiAgICBpZiAoZG93bmxvYWRfZGVmcy5yb2xlKSB7XG4gICAgICBjb25zdCBkb3dubG9hZF9kZWZzX3JvbGUgPSBgYXJuOiR7c3RhY2sucGFydGl0aW9ufTpzdHM6OiR7c3RhY2suYWNjb3VudH06YXNzdW1lZC1yb2xlLyR7ZG93bmxvYWRfZGVmcy5yb2xlLnJvbGVOYW1lfS8ke2Rvd25sb2FkX2RlZnMuZnVuY3Rpb25OYW1lfWA7XG4gICAgICBjb25zdCBkb3dubG9hZF9kZWZzX2Fzc3VtZWRfcHJpbmNpcGFsID0gbmV3IEFyblByaW5jaXBhbChcbiAgICAgICAgZG93bmxvYWRfZGVmc19yb2xlLFxuICAgICAgKTtcbiAgICAgIGRlZnNfYnVja2V0LmFkZFRvUmVzb3VyY2VQb2xpY3koXG4gICAgICAgIG5ldyBQb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgICAgIGVmZmVjdDogRWZmZWN0LkRFTlksXG4gICAgICAgICAgYWN0aW9uczogWydzMzpQdXRPYmplY3QqJ10sXG4gICAgICAgICAgcmVzb3VyY2VzOiBbZGVmc19idWNrZXQuYXJuRm9yT2JqZWN0cygnKicpXSxcbiAgICAgICAgICBub3RQcmluY2lwYWxzOiBbZG93bmxvYWRfZGVmcy5yb2xlLCBkb3dubG9hZF9kZWZzX2Fzc3VtZWRfcHJpbmNpcGFsXSxcbiAgICAgICAgfSksXG4gICAgICApO1xuICAgICAgZGVmc19idWNrZXQuZ3JhbnRSZWFkV3JpdGUoZG93bmxvYWRfZGVmcyk7XG4gICAgICBOYWdTdXBwcmVzc2lvbnMuYWRkUmVzb3VyY2VTdXBwcmVzc2lvbnMoZG93bmxvYWRfZGVmcy5yb2xlLCBbXG4gICAgICAgIHtcbiAgICAgICAgICBpZDogJ0F3c1NvbHV0aW9ucy1JQU00JyxcbiAgICAgICAgICByZWFzb246XG4gICAgICAgICAgICAnVGhlIEFXU0xhbWJkYUJhc2ljRXhlY3V0aW9uUm9sZSBkb2VzIG5vdCBwcm92aWRlIHBlcm1pc3Npb25zIGJleW9uZCB1cGxvYWRpbmcgbG9ncyB0byBDbG91ZFdhdGNoLicsXG4gICAgICAgIH0sXG4gICAgICBdKTtcbiAgICAgIE5hZ1N1cHByZXNzaW9ucy5hZGRSZXNvdXJjZVN1cHByZXNzaW9ucyhcbiAgICAgICAgZG93bmxvYWRfZGVmcy5yb2xlLFxuICAgICAgICBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICdBd3NTb2x1dGlvbnMtSUFNNScsXG4gICAgICAgICAgICByZWFzb246XG4gICAgICAgICAgICAgICdUaGUgZnVuY3Rpb24gaXMgYWxsb3dlZCB0byBpbnZva2UgdGhlIGRvd25sb2FkIGRlZnMgTGFtYmRhIGZ1bmN0aW9uLicsXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICk7XG4gICAgfVxuXG4gICAgbmV3IFJ1bGUodGhpcywgJ1ZpcnVzRGVmc1VwZGF0ZVJ1bGUnLCB7XG4gICAgICBzY2hlZHVsZTogU2NoZWR1bGUucmF0ZShEdXJhdGlvbi5ob3VycygxMikpLFxuICAgICAgdGFyZ2V0czogW25ldyBMYW1iZGFGdW5jdGlvbihkb3dubG9hZF9kZWZzKV0sXG4gICAgfSk7XG5cbiAgICBjb25zdCBpbml0X2RlZnNfY3IgPSBuZXcgRnVuY3Rpb24odGhpcywgJ0luaXREZWZzJywge1xuICAgICAgcnVudGltZTogUnVudGltZS5QWVRIT05fM184LFxuICAgICAgY29kZTogQ29kZS5mcm9tQXNzZXQoXG4gICAgICAgIHBhdGguam9pbihfX2Rpcm5hbWUsICcuLi9hc3NldHMvbGFtYmRhL2NvZGUvaW5pdGlhbGl6ZV9kZWZzX2NyJyksXG4gICAgICApLFxuICAgICAgaGFuZGxlcjogJ2xhbWJkYS5sYW1iZGFfaGFuZGxlcicsXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5taW51dGVzKDUpLFxuICAgIH0pO1xuICAgIGRvd25sb2FkX2RlZnMuZ3JhbnRJbnZva2UoaW5pdF9kZWZzX2NyKTtcbiAgICBpZiAoaW5pdF9kZWZzX2NyLnJvbGUpIHtcbiAgICAgIE5hZ1N1cHByZXNzaW9ucy5hZGRSZXNvdXJjZVN1cHByZXNzaW9ucyhcbiAgICAgICAgaW5pdF9kZWZzX2NyLnJvbGUsXG4gICAgICAgIFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJ0F3c1NvbHV0aW9ucy1JQU00JyxcbiAgICAgICAgICAgIHJlYXNvbjpcbiAgICAgICAgICAgICAgJ1RoZSBBV1NMYW1iZGFCYXNpY0V4ZWN1dGlvblJvbGUgZG9lcyBub3QgcHJvdmlkZSBwZXJtaXNzaW9ucyBiZXlvbmQgdXBsb2FkaW5nIGxvZ3MgdG8gQ2xvdWRXYXRjaC4nLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICdBd3NTb2x1dGlvbnMtSUFNNScsXG4gICAgICAgICAgICByZWFzb246XG4gICAgICAgICAgICAgICdUaGUgQVdTTGFtYmRhQmFzaWNFeGVjdXRpb25Sb2xlIGRvZXMgbm90IHByb3ZpZGUgcGVybWlzc2lvbnMgYmV5b25kIHVwbG9hZGluZyBsb2dzIHRvIENsb3VkV2F0Y2guJyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICB0cnVlLFxuICAgICAgKTtcbiAgICB9XG4gICAgbmV3IEN1c3RvbVJlc291cmNlKHRoaXMsICdJbml0RGVmc0NyJywge1xuICAgICAgc2VydmljZVRva2VuOiBpbml0X2RlZnNfY3IuZnVuY3Rpb25Bcm4sXG4gICAgICBwcm9wZXJ0aWVzOiB7XG4gICAgICAgIEZuTmFtZTogZG93bmxvYWRfZGVmcy5mdW5jdGlvbk5hbWUsXG4gICAgICB9LFxuICAgIH0pO1xuXG4gICAgaWYgKHByb3BzLmJ1Y2tldHMpIHtcbiAgICAgIHByb3BzLmJ1Y2tldHMuZm9yRWFjaCgoYnVja2V0KSA9PiB7XG4gICAgICAgIHRoaXMuYWRkU291cmNlQnVja2V0KGJ1Y2tldCk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogU2V0cyB0aGUgc3BlY2lmaWVkIFMzIEJ1Y2tldCBhcyBhIHMzOk9iamVjdENyZWF0ZSogZm9yIHRoZSBDbGFtQVYgZnVuY3Rpb24uXG4gICAgIEdyYW50cyB0aGUgQ2xhbUFWIGZ1bmN0aW9uIHBlcm1pc3Npb25zIHRvIGdldCBhbmQgdGFnIG9iamVjdHMuXG4gICAgIEFkZHMgYSBidWNrZXQgcG9saWN5IHRvIGRpc2FsbG93IEdldE9iamVjdCBvcGVyYXRpb25zIG9uIGZpbGVzIHRoYXQgYXJlIHRhZ2dlZCAnSU4gUFJPR1JFU1MnLCAnSU5GRUNURUQnLCBvciAnRVJST1InLlxuICAgKiBAcGFyYW0gYnVja2V0IFRoZSBidWNrZXQgdG8gYWRkIHRoZSBzY2FubmluZyBidWNrZXQgcG9saWN5IGFuZCBzMzpPYmplY3RDcmVhdGUqIHRyaWdnZXIgdG8uXG4gICAqL1xuICBhZGRTb3VyY2VCdWNrZXQoYnVja2V0OiBCdWNrZXQpIHtcbiAgICB0aGlzLl9zY2FuRnVuY3Rpb24uYWRkRXZlbnRTb3VyY2UoXG4gICAgICBuZXcgUzNFdmVudFNvdXJjZShidWNrZXQsIHsgZXZlbnRzOiBbRXZlbnRUeXBlLk9CSkVDVF9DUkVBVEVEXSB9KSxcbiAgICApO1xuICAgIGJ1Y2tldC5ncmFudFJlYWQodGhpcy5fc2NhbkZ1bmN0aW9uKTtcbiAgICB0aGlzLl9zY2FuRnVuY3Rpb24uYWRkVG9Sb2xlUG9saWN5KFxuICAgICAgbmV3IFBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgIGVmZmVjdDogRWZmZWN0LkFMTE9XLFxuICAgICAgICBhY3Rpb25zOiBbJ3MzOlB1dE9iamVjdFRhZ2dpbmcnLCAnczM6UHV0T2JqZWN0VmVyc2lvblRhZ2dpbmcnXSxcbiAgICAgICAgcmVzb3VyY2VzOiBbYnVja2V0LmFybkZvck9iamVjdHMoJyonKV0sXG4gICAgICB9KSxcbiAgICApO1xuXG4gICAgaWYgKHRoaXMuX3NjYW5GdW5jdGlvbi5yb2xlKSB7XG4gICAgICBjb25zdCBzdGFjayA9IFN0YWNrLm9mKHRoaXMpO1xuICAgICAgY29uc3Qgc2Nhbl9hc3N1bWVkX3JvbGUgPSBgYXJuOiR7c3RhY2sucGFydGl0aW9ufTpzdHM6OiR7c3RhY2suYWNjb3VudH06YXNzdW1lZC1yb2xlLyR7dGhpcy5fc2NhbkZ1bmN0aW9uLnJvbGUucm9sZU5hbWV9LyR7dGhpcy5fc2NhbkZ1bmN0aW9uLmZ1bmN0aW9uTmFtZX1gO1xuICAgICAgY29uc3Qgc2Nhbl9hc3N1bWVkX3ByaW5jaXBhbCA9IG5ldyBBcm5QcmluY2lwYWwoc2Nhbl9hc3N1bWVkX3JvbGUpO1xuICAgICAgdGhpcy5fczNHdy5hZGRUb1BvbGljeShcbiAgICAgICAgbmV3IFBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgICAgZWZmZWN0OiBFZmZlY3QuQUxMT1csXG4gICAgICAgICAgYWN0aW9uczogWydzMzpHZXRPYmplY3QqJywgJ3MzOkdldEJ1Y2tldConLCAnczM6TGlzdConXSxcbiAgICAgICAgICByZXNvdXJjZXM6IFtidWNrZXQuYnVja2V0QXJuLCBidWNrZXQuYXJuRm9yT2JqZWN0cygnKicpXSxcbiAgICAgICAgICBwcmluY2lwYWxzOiBbdGhpcy5fc2NhbkZ1bmN0aW9uLnJvbGUsIHNjYW5fYXNzdW1lZF9wcmluY2lwYWxdLFxuICAgICAgICB9KSxcbiAgICAgICk7XG4gICAgICB0aGlzLl9zM0d3LmFkZFRvUG9saWN5KFxuICAgICAgICBuZXcgUG9saWN5U3RhdGVtZW50KHtcbiAgICAgICAgICBlZmZlY3Q6IEVmZmVjdC5BTExPVyxcbiAgICAgICAgICBhY3Rpb25zOiBbJ3MzOlB1dE9iamVjdFRhZ2dpbmcnLCAnczM6UHV0T2JqZWN0VmVyc2lvblRhZ2dpbmcnXSxcbiAgICAgICAgICByZXNvdXJjZXM6IFtidWNrZXQuYXJuRm9yT2JqZWN0cygnKicpXSxcbiAgICAgICAgICBwcmluY2lwYWxzOiBbdGhpcy5fc2NhbkZ1bmN0aW9uLnJvbGUsIHNjYW5fYXNzdW1lZF9wcmluY2lwYWxdLFxuICAgICAgICB9KSxcbiAgICAgICk7XG5cbiAgICAgIC8vIE5lZWQgdGhlIGFzc3VtZWQgcm9sZSBmb3IgdGhlIG5vdCBQcmluY2lwYWwgQWN0aW9uIHdpdGggTGFtYmRhXG4gICAgICBidWNrZXQuYWRkVG9SZXNvdXJjZVBvbGljeShcbiAgICAgICAgbmV3IFBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgICAgZWZmZWN0OiBFZmZlY3QuREVOWSxcbiAgICAgICAgICBhY3Rpb25zOiBbJ3MzOkdldE9iamVjdCddLFxuICAgICAgICAgIHJlc291cmNlczogW2J1Y2tldC5hcm5Gb3JPYmplY3RzKCcqJyldLFxuICAgICAgICAgIG5vdFByaW5jaXBhbHM6IFt0aGlzLl9zY2FuRnVuY3Rpb24ucm9sZSwgc2Nhbl9hc3N1bWVkX3ByaW5jaXBhbF0sXG4gICAgICAgICAgY29uZGl0aW9uczoge1xuICAgICAgICAgICAgU3RyaW5nRXF1YWxzOiB7XG4gICAgICAgICAgICAgICdzMzpFeGlzdGluZ09iamVjdFRhZy9zY2FuLXN0YXR1cyc6IFtcbiAgICAgICAgICAgICAgICAnSU4gUFJPR1JFU1MnLFxuICAgICAgICAgICAgICAgICdJTkZFQ1RFRCcsXG4gICAgICAgICAgICAgICAgJ0VSUk9SJyxcbiAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSksXG4gICAgICApO1xuICAgIH1cbiAgfVxufVxuIl19