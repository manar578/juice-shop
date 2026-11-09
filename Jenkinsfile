pipeline {
    agent any

    environment {
        REPORTS = 'reports'
        IMAGE   = "juice-shop-local:${env.BUILD_NUMBER}"
    }

    stages {
        stage('Checkout GitHub') {
            steps {
                checkout scm
                // Nettoie les fichiers des builds précédents (évite un gitleaks.json de 15 Mo)
                sh 'git clean -fdx -e reports/ || true'
                sh 'rm -rf ${REPORTS} && mkdir -p ${REPORTS}'
            }
        }

        stage('Secrets Scan (Gitleaks)') {
            steps {
                sh '''
                  gitleaks detect --source . --no-git \
                    --report-format json --report-path ${REPORTS}/gitleaks.json \
                    --exit-code 0
                '''
            }
        }

        stage('SAST (Semgrep)') {
            steps {
                sh '''
                  semgrep scan --config p/owasp-top-ten --config p/nodejs \
                    --json --output ${REPORTS}/semgrep.json \
                    --metrics=off routes lib server.ts
                '''
            }
        }

        stage('SCA - Dépendances (Trivy)') {
            steps {
                sh '''
                  npm install --package-lock-only --package-lock=true --ignore-scripts
                  trivy fs --scanners vuln --format json \
                    --output ${REPORTS}/trivy-fs.json .
                  trivy fs --scanners vuln --severity CRITICAL \
                    --ignore-unfixed --exit-code 0 .
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t ${IMAGE} .'
            }
        }

        stage('Docker Image Scan (Trivy)') {
            steps {
                sh '''
                  trivy image --format json --output ${REPORTS}/trivy-image.json ${IMAGE}
                  trivy image --severity CRITICAL --ignore-unfixed --exit-code 0 ${IMAGE}
                '''
            }
        }

        stage('Deploy Staging') {
            steps {
                sh '''
                  docker rm -f juice-staging || true
                  docker run -d --name juice-staging -p 3001:3000 ${IMAGE}
                  sleep 30
                  curl -sf http://localhost:3001 > /dev/null
                '''
            }
        }

        stage('DAST (OWASP ZAP)') {
            steps {
                sh '''
                  chmod 777 ${REPORTS}
                  docker run --rm --network host -v $(pwd)/${REPORTS}:/zap/wrk:rw \
                    ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                    -t http://localhost:3001 -r zap-report.html -J zap-report.json -I
                '''
            }
        }
    }

    post {
        always {
            sh 'docker rm -f juice-staging || true'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure { echo 'Pipeline BLOQUÉ par une quality gate.' }
        success { echo 'Toutes les quality gates sont passées.' }
    }
}
