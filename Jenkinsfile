pipeline {
    agent any

    stages {
        stage('Checkout GitHub') {
            steps {
                checkout scm
            }
        }

        stage('Verify Checkout') {
            steps {
                sh 'pwd'
                sh 'ls -la'
                echo 'Juice Shop (fork manar578) récupéré depuis GitHub !'
            }
        }
    }
}
