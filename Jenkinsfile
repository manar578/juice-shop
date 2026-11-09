pipeline {
    agent any

    environment {
        REPORTS = 'reports'
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
                    --exit-code 1
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure { echo 'Pipeline BLOQUÉ : secrets détectés.' }
        success { echo 'Aucun secret détecté.' }
    }
}
