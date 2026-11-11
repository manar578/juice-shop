pipeline {
    agent any

    parameters {
        booleanParam(name: 'ENFORCE_GATES', defaultValue: true,
                     description: 'true = quality gates bloquantes')
    }

    environment {
        REPORTS = 'reports'
        IMAGE   = "juice-shop-local:${env.BUILD_NUMBER}"
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

        // GATE 1 : secrets (exemptions dans .gitleaks.toml et .gitleaksignore)
        stage('Secrets Scan (Gitleaks)') {
            steps {
                sh '''
                  gitleaks detect --source . --no-git --config .gitleaks.toml \
                    --report-format json --report-path ${REPORTS}/gitleaks.json \
                    --exit-code ${GATE}
                '''
            }
        }

        // GATE 2 : SAST (ERROR bloque, sauf nosemgrep documentés)
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

        // GATE 3 : SCA (CRITICAL, correctif disponible, sauf .trivyignore)
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

        // GATE 5 : DAST (une alerte High bloque ; Medium/Low seulement rapportées)
        stage('DAST (OWASP ZAP)') {
            steps {
                sh '''
                  chmod 777 ${REPORTS}
                  docker run --rm --network host -v $(pwd)/${REPORTS}:/zap/wrk:rw \
                    ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                    -t http://localhost:3001 -r zap-report.html -J zap-report.json -I

                  python3 -c "
import json, sys
d = json.load(open('${REPORTS}/zap-report.json'))
high = [a['name'] for s in d['site'] for a in s['alerts'] if int(a['riskcode']) >= 3]
print('Alertes High :', high)
sys.exit(1 if (high and '${GATE}' == '1') else 0)
"
                '''
            }
        }

        // DEPLOIEMENT : atteint seulement si TOUS les contrôles précédents sont verts.
        // L'application reste en ligne sur le port 3002 après le build.
        stage('Deploy (port 3002)') {
            when { expression { params.ENFORCE_GATES } }
            steps {
                sh '''
                  docker rm -f juice-prod || true
                  docker run -d --name juice-prod --restart unless-stopped -p 3002:3000 ${IMAGE}
                  sleep 30
                  curl -sf http://localhost:3002 > /dev/null
                  echo "Application déployée : http://$(hostname -I | awk '{print $1}'):3002"
                '''
            }
        }
    }

       post {
        always {
            sh 'docker rm -f juice-staging || true'
            sh 'python3 scripts/make_report.py || true'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure {
            echo 'Pipeline BLOQUÉ par une quality gate de sécurité.'
            mail to: 'manaratallah335@gmail.com',
                 subject: "[Jenkins] BLOQUÉ : ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                 body: "Le pipeline DevSecOps a été bloqué par une quality gate.\n\nJob : ${env.JOB_NAME}\nBuild : #${env.BUILD_NUMBER}\nConsole : ${env.BUILD_URL}console\nRapports : ${env.BUILD_URL}artifact/"
        }
        success {
            echo 'Toutes les quality gates sont passées, application déployée sur le port 3002.'
        }
    }
}
