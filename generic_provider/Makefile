compile-libs:
	@docker run --rm \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  -v `pwd`:/src \
	  -w /src \
	  amazonlinux:latest \
	  bash -c 'yum update -y\
	   && yum groupinstall "Development Tools" -y\
	   && yum install -y python-pip ibffi openssl-devel\
	   && pip install --upgrade pip\
	   && pip install --upgrade -r ./requirements.txt -t .'

.PHONY: compile-libs
