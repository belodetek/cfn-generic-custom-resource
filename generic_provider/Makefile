compile-libs:
	@docker run --rm \
	  -v `pwd`:/src \
	  -w /src \
	  amazonlinux:latest \
	  bash -c '''pwd && ls -la .\
	    && yum update -y\
	    && yum groupinstall "Development Tools" -y\
	    && yum install -y python-pip ibffi openssl-devel\
	    && pip install virtualenv\
	    && export VIRTUAL_ENV=/src/venv2\
	    && python -m virtualenv $${VIRTUAL_ENV}\
	    && export PATH="$${VIRTUAL_ENV}/bin:$${PATH}"\
	    && pip install --upgrade pip\
	    && pip install --upgrade -r ./requirements.txt -t .'''

.PHONY: compile-libs
