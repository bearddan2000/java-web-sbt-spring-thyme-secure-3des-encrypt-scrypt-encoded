# java-web-sbt-spring-thyme-secure-3des-encrypt-scrypt-encoded

## Description
A springboot secure web app with thymeleaf support.
Three roles are defined; USER, ADMIN, and SUPER. All roles
can access pages `/home`, `/login`, and `/about`. Only USER
can access `/user` and ADMIN only `/admin` whereas SUPER can
navigate to either and have its own `/super`. Each role
has an action USER=VIEW ONLY, ADMIN=READ/WRITE, SUPER=CREATE.
All password are encrypted with 3DES and encoded with scrypt
to insure strong passwords.

3-DES is a 128 byte encryption but a 256 byte AES generated key
was used for the md5 digest password.

## Tech stack
- java
- sbt
  - springboot
  - thymeleaf
  - bootstrap
  - jquery
  - datatable

## Docker stack
- openjdk:8-jdk-alpine

## To run
`sudo ./install.sh -u`
Available at http://localhost
- Login with id: user and password: pass
- Login with id: admin and password: pass
- Login with id: super and password: pass

## To stop (optional)
`sudo ./install.sh -d`

## For help
`sudo ./install.sh -h`

## Credit
[Code concept] (https://stackoverflow.com/questions/20227/how-do-i-use-3des-encryption-decryption-in-java)
