pipeline{
    agent any
    environment{
        MYSQL_DATABASE_PASSWORD = "Clarusway"
        MYSQL_DATABASE_USER = "admin"
        MYSQL_DATABASE_DB = "phonebook"
        MYSQL_DATABASE_PORT = 3306
        PATH="/usr/local/bin/:${env.PATH}"
        ECR_REGISTRY = "646075469151.dkr.ecr.us-east-1.amazonaws.com"
        APP_REPO = "phonebook/app"
        AWS_ACCOUNT_ID=sh(script:'export PATH="$PATH:/usr/local/bin" && aws sts get-caller-identity --query Account --output text', returnStdout:true).trim()
        APP_REPO_NAME = "mehmetafsar510"
        AWS_REGION = "us-east-1"
        CLUSTER_NAME = "mehmet-cluster"
        FQDN = "clarusshop.mehmetafsar.com"
        DOMAIN_NAME = "mehmetafsar.com"
        NM_SP = "phone"
        GIT_FOLDER = sh(script:'echo ${GIT_URL} | sed "s/.*\\///;s/.git$//"', returnStdout:true).trim()
    }
    stages{
        stage('Setup kubectl helm and eksctl binaries') {
            steps {
              script {

                println "Getting the kubectl helm and eksctl binaries..."
                sh """
                  curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_\$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
                  curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.17.9/2020-08-04/bin/linux/amd64/kubectl
                  curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
                  chmod 700 get_helm.sh
                  chmod +x ./kubectl
                  sudo mv ./kubectl /usr/local/bin
                  sudo mv /tmp/eksctl /usr/local/bin
                  ./get_helm.sh
                """
              }
            }
        } 

        stage("compile"){
           agent{
               docker{
                   image 'python:alpine'
               }
           }
           steps{
               withEnv(["HOME=${env.WORKSPACE}"]) {
                    sh 'pip install -r requirements.txt'
                    sh 'python -m py_compile src/*.py'
                    stash(name: 'compilation_result', includes: 'src/*.py*')
                }
           }
        }

        stage('creating RDS for test stage'){
            agent any
            steps{
                echo 'creating RDS for test stage'
                sh '''
                    RDS=$(aws rds describe-db-instances | grep mysql-instance |cut -d '"' -f 4| head -n 1)  || true
                    if [ "$RDS" == '' ]
                    then
                        aws rds create-db-instance \
                          --db-instance-identifier mysql-instance \
                          --db-instance-class db.t2.micro \
                          --engine mysql \
                          --db-name ${MYSQL_DATABASE_DB} \
                          --master-username ${MYSQL_DATABASE_USER} \
                          --master-user-password ${MYSQL_DATABASE_PASSWORD} \
                          --allocated-storage 20 \
                          --tags 'Key=Name,Value=masterdb'
                          
                    fi
                '''
            script {
                while(true) {
                        
                        echo "RDS is not UP and running yet. Will try to reach again after 10 seconds..."
                        sleep(10)

                        endpoint = sh(script:'aws rds describe-db-instances --region ${AWS_REGION} --query DBInstances[*].Endpoint.Address --output text | sed "s/\\s*None\\s*//g"', returnStdout:true).trim()

                        if (endpoint.length() >= 7) {
                            echo "My Database Endpoint Address Found: $endpoint"
                            env.MYSQL_DATABASE_HOST = "$endpoint"
                            break
                        }
                    }
                }
            }
        }

        stage('create phonebook table in rds'){
            agent any
            steps{
                sh "mysql -u ${MYSQL_DATABASE_USER} -h ${MYSQL_DATABASE_HOST} -p${MYSQL_DATABASE_PASSWORD} < phonebook.sql"
            }
        } 
       
        stage('test'){
            agent {
                docker {
                    image 'python:alpine'
                }
            }
            steps {
                withEnv(["HOME=${env.WORKSPACE}"]) {
                    sh 'python -m pytest -v --junit-xml results.xml src/appTest.py'
                }
            }
            post {
                always {
                    junit 'results.xml'
                }
            }
        }  

        stage('creating .env for docker-compose'){
            agent any
            steps{
                script {
                    echo 'creating .env for docker-compose'
                    sh "cd ${WORKSPACE}"
                    writeFile file: '.env', text: "ECR_REGISTRY=${ECR_REGISTRY}\nAPP_REPO_NAME=${APP_REPO}:latest"
                }
            }
        }

        stage('creating ECR Repository'){
            agent any
            steps{
                echo 'creating ECR Repository'
                sh '''
                    RepoArn=$(aws ecr describe-repositories | grep ${APP_REPO} |cut -d '"' -f 4| head -n 1 )  || true
                    if [ "$RepoArn" == '' ]
                    then
                        aws ecr create-repository \
                          --repository-name ${APP_REPO} \
                          --image-scanning-configuration scanOnPush=false \
                          --image-tag-mutability MUTABLE \
                          --region ${AWS_REGION}
                        
                    fi
                '''
            }
        } 

        stage('build'){
            agent any
            steps{
                sh "docker build -t ${APP_REPO} ."
                sh 'docker tag ${APP_REPO} "$ECR_REGISTRY/$APP_REPO:latest"'
            }
        }

        stage('push'){
            agent any
            steps{
                sh 'aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin "$ECR_REGISTRY"'
                sh 'docker push "$ECR_REGISTRY/$APP_REPO:latest"'
            }
        }

        stage('compose'){
            agent any
            steps{
                sh 'aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin "$ECR_REGISTRY"'
                sh "docker-compose up -d"
            }
        }

        stage('Build Docker Result Image') {
			steps {
				sh 'docker build -t phonebook:latest ${GIT_URL}#:result'
				sh 'docker tag phonebook:latest $APP_REPO_NAME/phonebook-result:latest'
				sh 'docker tag phonebook:latest $APP_REPO_NAME/phonebook-result:${BUILD_ID}'
				sh 'docker images'
			}
		}
        stage('Build Docker Update Image') {
			steps {
				sh 'docker build -t phonebook:latest ${GIT_URL}#:kubernetes'
				sh 'docker tag phonebook:latest $APP_REPO_NAME/phonebook-update:latest'
				sh 'docker tag phonebook:latest $APP_REPO_NAME/phonebook-update:${BUILD_ID}'
				sh 'docker images'
			}
		}
		stage('Push Result Image to Docker Hub') {
			steps {
				withDockerRegistry([ credentialsId: "dockerhub_id", url: "" ]) {
				sh 'docker push $APP_REPO_NAME/phonebook-update:latest'
				sh 'docker push $APP_REPO_NAME/phonebook-update:${BUILD_ID}'
				}
			}
		}
        stage('Push Update Image to Docker Hub') {
			steps {
				withDockerRegistry([ credentialsId: "dockerhub_id", url: "" ]) {
				sh 'docker push $APP_REPO_NAME/phonebook-result:latest'
				sh 'docker push $APP_REPO_NAME/phonebook-result:${BUILD_ID}'
				}
			}
		}

        stage('get-keypair'){
            agent any
            steps{
                sh '''
                    if [ -f "${CFN_KEYPAIR}.pem" ]
                    then 
                        echo "file exists..."
                    else
                        aws ec2 create-key-pair \
                          --region ${AWS_REGION} \
                          --key-name ${CFN_KEYPAIR}.pem \
                          --query KeyMaterial \
                          --output text > ${CFN_KEYPAIR}.pem

                        chmod 400 ${CFN_KEYPAIR}.pem

                        ssh-keygen -y -f ${CFN_KEYPAIR}.pem >> the_doctor_public.pem
                    fi
                '''                
            }
        }

        stage('create-cluster'){
            agent any
            steps{
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                    sh '''
                        Cluster=$(eksctl get cluster --region ${AWS_REGION} | grep ${CLUSTER_NAME})  || true
                        if [ "$Cluster" == '' ]
                        then
                            eksctl create cluster \
                                --version 1.17 \
                                --region ${AWS_REGION} \
                                --ssh-access=true \
                                --ssh-public-key=the_doctor_public.pem \
                                --node-type t2.medium \
                                --with-oidc \
                                --managed \
                                --nodegroup-name ${CLUSTER_NAME}-0 \
                                --nodes 1 --nodes-min 1 --nodes-max 2 \
                                --node-volume-size 8 --name ${CLUSTER_NAME} \
                                --zones us-east-1a,us-east-1b,us-east-1c,us-east-1d,us-east-1f
                        else
                            echo "${CLUSTER_NAME} has already created..."

                        fi
                    '''
                }    
            }
        }

        stage('Setting up Cloudwatch logs'){
            agent any
            steps{
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                    echo "Setting up Cloudwatch logs."
                    sh "eksctl utils update-cluster-logging --enable-types all --approve --cluster ${CLUSTER_NAME}"
                }    
            }
        }

        stage('Cloudwatch metrics and Container Insights setup'){
            agent any
            steps{
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                    script {
                        
                        env.ROLE_ARN = sh(script:"aws eks describe-nodegroup --nodegroup-name ${CLUSTER_NAME}-0 --cluster-name ${CLUSTER_NAME} --query nodegroup.nodeRole --output text | cut -d '/' -f 2", returnStdout:true).trim()
                    }
                    echo "Cluster setup."
                    sh "aws eks update-kubeconfig --name ${CLUSTER_NAME} --region ${AWS_REGION}"

                    echo "Setting up Cloudwatch metrics and Container Insights."
                    sh "curl --silent https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluentd-quickstart.yaml >> cwagent-fluentd-quickstart.yaml"
                    sh "sed -i 's|{{cluster_name}}|${CLUSTER_NAME}|g' cwagent-fluentd-quickstart.yaml"
                    sh "sed -i 's|{{region_name}}|${AWS_REGION}|g' cwagent-fluentd-quickstart.yaml"
                    sh "kubectl apply --validate=false -f cwagent-fluentd-quickstart.yaml"   
                    sh """
                      aws iam attach-role-policy --role-name ${ROLE_ARN} --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
                    """
                }    
            }
        }

        stage('Test the cluster') {
            steps {
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                    echo "Testing if the K8s cluster is ready or not"
                script {
                    while(true) {
                        try {
                          sh "kubectl get nodes | grep -i Ready"
                          echo "Successfully created  EKS cluster."
                          break
                        }
                        catch(Exception) {
                          echo 'Could not get cluster please wait'
                          sleep(5)  
                        } 
                    }
                }
            }
        }
    }

        stage('check-cluster'){
            agent any
            steps{
                sh '''
                    #!/bin/sh
                    running=$(sudo lsof -nP -iTCP:80 -sTCP:LISTEN) || true
                    
                    if [ "$running" != '' ]
                    then
                        docker-compose down
                        exist="$(eksctl get cluster | grep ${CLUSTER_NAME})" || true

                        if [ "$exist" == '' ]
                        then
                            
                            echo "we have already created this cluster...."
                        else
                            echo 'no need to create cluster...'
                        fi
                    else
                        echo 'app is not running with docker-compose up -d'
                    fi
                '''
            }
        }

        stage('apply-k8s'){
            agent any
            steps{
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                    sh "sed -i 's|{{REGISTRY}}|$APP_REPO_NAME/phonebook-update|g' kubernetes/update-deployment.yaml"
                    sh "sed -i 's|{{REGISTRY}}|$APP_REPO_NAME/phonebook-result|g' result/result-deployment.yml"
                    sh '''
                        NameSpaces=$(kubectl get namespaces | grep -i $NM_SP) || true
                        if [ "$NameSpaces" == '' ]
                        then
                            kubectl create namespace $NM_SP
                        else
                            kubectl delete namespace $NM_SP
                            kubectl create namespace $NM_SP
                        fi
                    '''
                    sh "sed -i 's|{{ns}}|$NM_SP|g' kubernetes/servers-configmap.yaml"
                    sh "sed -i 's|{{ns}}|$NM_SP|g' storage-ns.yml"
                    sh "kubectl apply -f  storage-class.yaml"
                    sh "kubectl apply -f  storage-ns.yml"
                    sh "kubectl apply --namespace $NM_SP -f  result"
                    sh "kubectl apply --namespace $NM_SP -f  kubernetes"
                    sh "kubectl apply --namespace $NM_SP -f  auto-scaling"
                    sh "kubectl apply -f  components.yaml"
                    sh "curl -o iam_policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.2.0/docs/install/iam_policy.json"
                    sh '''
                        policy=$(aws iam list-policies | grep -i AWSLoadBalancerControllerIAMPolicy)  || true
                        if [ "$policy" == '' ]
                        then
                            aws iam create-policy \
                                --policy-name AWSLoadBalancerControllerIAMPolicy \
                                --policy-document file://iam_policy.json
                        else
                            echo "AWSLoadBalancerControllerIAMPolicy has already created..."

                        fi
                    '''
                    sh '''
                        serviceaccount=$(eksctl get iamserviceaccount --cluster ${CLUSTER_NAME} | grep -i aws-load-balancer-controller)  || true
                        if [ "$serviceaccount" == '' ]
                        then
                            eksctl create iamserviceaccount \
                              --cluster=${CLUSTER_NAME} \
                              --namespace=kube-system \
                              --name=aws-load-balancer-controller \
                              --attach-policy-arn=arn:aws:iam::${AWS_ACCOUNT_ID}:policy/AWSLoadBalancerControllerIAMPolicy \
                              --override-existing-serviceaccounts \
                              --approve
                        else
                            echo "aws-load-balancer-controller has already created..."

                        fi
                    '''
                    sh 'kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller/crds?ref=master"'
                    sh "helm repo add eks https://aws.github.io/eks-charts"
                    sh "helm repo update"
                    sh """
                    helm upgrade -i aws-load-balancer-controller eks/aws-load-balancer-controller \
                      --set clusterName=${CLUSTER_NAME} \
                      --set serviceAccount.create=false \
                      --set serviceAccount.name=aws-load-balancer-controller \
                      -n kube-system
                    """
                    sh "helm uninstall aws-load-balancer-controller -n kube-system"
                    sh """
                    helm upgrade -i aws-load-balancer-controller eks/aws-load-balancer-controller \
                      --set clusterName=${CLUSTER_NAME} \
                      --set serviceAccount.create=false \
                      --set serviceAccount.name=aws-load-balancer-controller \
                      -n kube-system
                    """
                    sh '''
                        extpolicy=$(aws iam list-policies | grep -i AllowExternalDNSUpdates)  || true
                        if [ "$extpolicy" == '' ]
                        then
                            aws iam create-policy \
                                --policy-name AllowExternalDNSUpdates \
                                --policy-document file://extpolicy.json
                        else
                            echo "AllowExternalDNSUpdates has already created..."

                        fi
                    '''
                    sh '''
                        serviceaccountdns=$(eksctl get iamserviceaccount --cluster ${CLUSTER_NAME} | grep -i external-dns)  || true
                        if [ "$serviceaccountdns" == '' ]
                        then
                            eksctl create iamserviceaccount \
                              --cluster=${CLUSTER_NAME} \
                              --namespace default\
                              --name=external-dns \
                              --attach-policy-arn=arn:aws:iam::${AWS_ACCOUNT_ID}:policy/AllowExternalDNSUpdates \
                              --override-existing-serviceaccounts \
                              --approve
                        else
                            echo "external-dns has already created..."

                        fi
                    '''
                }                  
            }
        }

        stage('Test the aws-load-balancer-controller and external role') {
            steps {
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                    script {
                        
                        env.ARN = sh(script:"aws cloudformation describe-stacks --stack-name eksctl-mehmet-cluster-addon-iamserviceaccount-default-external-dns | grep -i OutputValue | cut -d'\"' -f 4", returnStdout:true).trim()
                    }
                    echo "Testing if the aws-load-balancer-controller role is ready or not"
                script {
                    while(true) {
                        try {
                          sh "aws cloudformation describe-stacks --stack-name eksctl-mehmet-cluster-addon-iamserviceaccount-kube-system-aws-load-balancer-controller --output text | grep -i CREATE_COMPLETE | tail -n 1 | cut -f8"
                          echo "Successfully created  aws-load-balancer-controller role."
                          sh "kubectl get sa external-dns"
                          sh "sed -i 's|{{role-arn}}|$ARN|g' externalDNS.yml"
                          sh "sed -i 's|{{DOMAIN_NAME}}|$DOMAIN_NAME|g' externalDNS.yml"
                          sh "kubectl apply -f externalDNS.yml"
                          sleep(15)
                          break
                        }
                        catch(Exception) {
                          echo 'Could not get aws-load-balancer-controller role please wait'
                          sleep(5)  
                        } 
                    }
                }
            }
        }
    }

        stage('dns-record-control'){
            agent any
            steps{
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                    script {
                        
                        env.ZONE_ID = sh(script:"aws route53 list-hosted-zones-by-name --dns-name $DOMAIN_NAME --query HostedZones[].Id --output text | cut -d/ -f3", returnStdout:true).trim()
                        env.ELB_DNS = sh(script:"aws route53 list-resource-record-sets --hosted-zone-id $ZONE_ID --query \"ResourceRecordSets[?Name == '\$FQDN.']\" --output text | tail -n 1 | cut -f2", returnStdout:true).trim()  
                    }
                    sh "sed -i 's|{{DNS}}|$ELB_DNS|g' deleterecord.json"
                    sh "sed -i 's|{{FQDN}}|$FQDN|g' deleterecord.json"
                    sh '''
                        RecordSet=$(aws route53 list-resource-record-sets   --hosted-zone-id $ZONE_ID   --query ResourceRecordSets[] | grep -i $FQDN) || true
                        if [ "$RecordSet" != '' ]
                        then
                            aws route53 change-resource-record-sets --hosted-zone-id $ZONE_ID --change-batch file://deleterecord.json
                        
                        fi
                    '''
                    
                }                  
            }
        }

        stage('Aws-Certificate-Manager'){
            agent any
            steps{
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {

                    sh '''
                        Acm=$(aws acm list-certificates --query CertificateSummaryList[].[CertificateArn,DomainName] --output text | grep $FQDN) || true
                        if [ "$Acm" == '' ]
                        then
                            aws acm request-certificate --domain-name $FQDN --validation-method DNS --query CertificateArn --region ${AWS_REGION}
                        
                        fi
                    '''
                        
                }                  
            }
        }

        stage('ssl-tls-record-validate'){
            agent any
            steps{
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                    script {
                        env.ZONE_ID = sh(script:"aws route53 list-hosted-zones-by-name --dns-name $DOMAIN_NAME --query HostedZones[].Id --output text | cut -d/ -f3", returnStdout:true).trim() 
                        env.SSL_CERT_ARN = sh(script:"aws acm list-certificates --query CertificateSummaryList[].[CertificateArn,DomainName]   --output text | grep $FQDN | cut -f1", returnStdout:true).trim()
                        env.SSL_CERT_NAME = sh(script:"aws acm describe-certificate --certificate-arn $SSL_CERT_ARN --query Certificate.DomainValidationOptions --output text | tail -n 1 | cut -f2", returnStdout:true).trim()
                        env.SSL_CERT_VALUE = sh(script:"aws acm describe-certificate --certificate-arn $SSL_CERT_ARN --query Certificate.DomainValidationOptions --output text | tail -n 1 | cut -f4", returnStdout:true).trim()   
                    }

                    sh "sed -i 's|{{SSL_CERT_NAME}}|$SSL_CERT_NAME|g' deletecertificate.json"
                    sh "sed -i 's|{{SSL_CERT_VALUE}}|$SSL_CERT_VALUE|g' deletecertificate.json"

                    sh '''
                        SSLRecordSet=$(aws route53 list-resource-record-sets   --hosted-zone-id $ZONE_ID   --query ResourceRecordSets[] | grep -i $SSL_CERT_NAME) || true
                        if [ "$SSLRecordSet" != '' ]
                        then
                            aws route53 change-resource-record-sets --hosted-zone-id $ZONE_ID --change-batch file://deletecertificate.json
                        
                        fi
                    '''

                    sh "sed -i 's|{{SSL_CERT_NAME}}|$SSL_CERT_NAME|g' certificate.json"
                    sh "sed -i 's|{{SSL_CERT_VALUE}}|$SSL_CERT_VALUE|g' certificate.json"
                    sh "aws route53 change-resource-record-sets --hosted-zone-id $ZONE_ID --change-batch file://certificate.json"
                    
                    sleep(5)
                                  
                }                  
            }
        }
        stage('k8s-ingress') {
            steps {
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                script {
                    while(true) {
                        try {
                          sh "sudo mv -f ingress-https.yaml ingress.yaml" 
                          sh "sed -i 's|{{FQDN}}|$FQDN|g' ingress.yaml"
                          sh "sed -i 's|{{ARN}}|$SSL_CERT_ARN|g' ingress.yaml"
                          sh "kubectl apply --namespace $NM_SP -f ingress.yaml"
                          sleep(15)
                          break
                        }
                        catch(Exception) {
                          echo 'Could not get aws-load-balancer-controller role please wait'
                          sleep(5)  
                        } 
                    }
                }
            }
        }
    }
        stage('Prometheus-Grafana'){
            agent any
            steps{
                withAWS(credentials: 'mycredentials', region: 'us-east-1') {

                    sh '''
                        NameSpaces=$(kubectl get namespaces | grep -i prometheus) || true
                        if [ "$NameSpaces" == '' ]
                        then
                            kubectl create namespace prometheus
                            kubectl apply --namespace prometheus -f prometheus
                            kubectl apply -f store.yml
                            kubectl apply --namespace prometheus -f grafana
                            kubectl get svc --namespace prometheus
                        else
                            echo "Prometheus namespace has already created"

                            fi
                    '''       
                }                  
            }
        }
    
    }
    post {
        always {
            echo 'Deleting all local images'
            sh 'docker image prune -af'
        }
        failure {
            withAWS(credentials: 'mycredentials', region: 'us-east-1') {
                sh "rm -rf '${WORKSPACE}/.env'"
                sh "helm uninstall aws-load-balancer-controller -n kube-system"
                sh """
                aws ec2 detach-volume \
                  --volume-id ${EBS_VOLUME_ID} \
                """
                sh """
                aws ecr delete-repository \
                  --repository-name ${APP_REPO_NAME} \
                  --region ${AWS_REGION}\
                  --force
                """
                sh """
                aws rds delete-db-instance \
                  --db-instance-identifier mysql-instance \
                  --skip-final-snapshot \
                  --delete-automated-backups
                """
                sh """
                aws ec2 delete-key-pair \
                  --key-name ${CFN_KEYPAIR}.pem
                """
                sh "rm -rf '${WORKSPACE}/the_doctor_public.pem'"
                sh "rm -rf '${WORKSPACE}/${CFN_KEYPAIR}.pem'"
                sh "eksctl delete cluster ${CLUSTER_NAME}"
                sh "docker rm -f '\$(docker ps -a -q)'"
            } 
        }
        success {
            echo "You are Greattt...You can visit https://$FQDN"
        }
    }
}

