Docker Security Audit
=================================  

Overview:
--------------  
This is a DIND (docker in docker) image that will check your docker containers
for vulnerable versions of bash and openssl. It can additionally generate
lynis security reports. It returns 0 on a clean audit, and 1 otherwise.  

Flags:
----------------
-h Hound_URL  : Specify a hound url to search your docker compose files for images  
-i image,list : Specify a comma delimited list of images to check  
-v : Verbosity on. If left out, this script will only output a pass or fail message  
-l : Besides the base checks, additionally run a lynis scan for each image. Use in conjunction
with -v  


Usage:
----------------
You must specify either the h or i flag, all other are optional.  
```
docker run --privileged --entrypoint=wrapdocker --rm nyxcharon/docker-audit docker-audit -v -l -h http://someurl.com
```
