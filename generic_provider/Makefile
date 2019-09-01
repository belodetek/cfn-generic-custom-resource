all: clean compile-libs

compile-libs:
	@docker run --rm \
	  -v `pwd`:/src \
	  -w /src \
	  lambci/lambda:build-python2.7 \
	  bash -c '''pwd && ls -la .\
	    && yum update -y\
	    && yum groupinstall "Development Tools" -y\
	    && yum install -y python-pip ibffi openssl-devel\
	    && pip install virtualenv\
	    && export VIRTUAL_ENV=/src/venv2\
	    && python -m virtualenv $${VIRTUAL_ENV}\
	    && export PATH="$${VIRTUAL_ENV}/bin:$${PATH}"\
	    && pip install --upgrade pip\
	    && pip install --upgrade --force -r ./requirements.txt -t .\
	    && find . -name "*.so"'''

clean:
	@rm -rf enum* venv*; find . -name '*.so' -delete

.PHONY: all
