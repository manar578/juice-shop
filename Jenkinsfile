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
                sh 'mkdir -p ${REPORTS}'
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
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure { echo 'Pipeline BLOQUÉ par une quality gate.' }
        success { echo 'Toutes les quality gates sont passées.' }
    }
}
