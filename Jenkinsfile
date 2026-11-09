pipeline {
    agent any

    parameters {
        booleanParam(name: 'ENFORCE_GATES', defaultValue: true,
                     description: 'true = quality gates bloquantes')
    }

    environment {
        REPORTS = 'reports'
        IMAGE   = "juice-shop-local:${env.BUILD_NUMBER}"
        // exit code utilisé par les gates : 1 si bloquant, 0 sinon
        GATE    = "${params.ENFORCE_GATES ? '1' : '0'}"
    }

    stages {
        stage('Checkout GitHub') {
            steps {
                checkout scm
                sh 'git clean -fdx -e reports/ || true'
                sh 'rm -rf ${REPORTS} && mkdir -p ${REPORTS}'
            }
        }

        // GATE 1 : secrets (toute fuite détectée bloque, sauf .gitleaksignore)
        stage('Secrets Scan (Gitleaks)') {
            steps {
                sh '''
                  gitleaks detect --source . --no-git \
                    --report-format json --report-path ${REPORTS}/gitleaks.json \
                    --exit-code ${GATE}
                '''
            }
        }

        // GATE 2 : SAST (findings de sévérité ERROR bloquent)
        stage('SAST (Semgrep)') {
            steps {
                sh '''
                  semgrep scan --config p/owasp-top-ten --config p/nodejs \
                    --json --output ${REPORTS}/semgrep.json \
                    --metrics=off routes lib server.ts

                  if [ "${GATE}" = "1" ]; then
                    semgrep scan --config p/owasp-top-ten --config p/nodejs \
                      --severity ERROR --error --metrics=off routes lib server.ts
                  fi
                '''
            }
        }

        // GATE 3 : SCA (CRITICAL, CVSS >= 9.0, correctif disponible)
        stage('SCA - Dépendances (Trivy)') {
            steps {
                sh '''
                  npm install --package-lock-only --package-lock=true --ignore-scripts
                  trivy fs --scanners vuln --format json \
                    --output ${REPORTS}/trivy-fs.json .
                  trivy fs --scanners vuln --severity CRITICAL \
                    --ignore-unfixed --exit-code ${GATE} .
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t ${IMAGE} .'
            }
        }

        // GATE 4 : image Docker
        stage('Docker Image Scan (Trivy)') {
            steps {
                sh '''
                  trivy image --format json --output ${REPORTS}/trivy-image.json ${IMAGE}
                  trivy image --severity CRITICAL --ignore-unfixed \
                    --exit-code ${GATE} ${IMAGE}
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

        // GATE 5 : DAST (alertes de niveau FAIL bloquent ; sans -I)
        stage('DAST (OWASP ZAP)') {
            steps {
                sh '''
                  chmod 777 ${REPORTS}
                  if [ "${GATE}" = "1" ]; then OPT=""; else OPT="-I"; fi
                  docker run --rm --network host -v $(pwd)/${REPORTS}:/zap/wrk:rw \
                    ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                    -t http://localhost:3001 -r zap-report.html -J zap-report.json $OPT
                '''
            }
        }
    }

    post {
        always {
            sh 'docker rm -f juice-staging || true'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure { echo 'Pipeline BLOQUÉ par une quality gate de sécurité.' }
        success { echo 'Toutes les quality gates sont passées.' }
    }
}
