all: clean compile-libs debug

compile-libs:
	@mkdir -p build \
          && cat requirements.txt > build/requirements.txt \
          && cat Makefile > build/Makefile \
          && cp generic_provider.py cfnresponse.py\
          acm_pca.py autoscaling.py build/ \
          && docker run --rm \
	  -v `pwd`/build:/src \
	  -w /src \
	  lambci/lambda:build-python3.7 \
	  bash -c '''yum update -y\
	    && yum groupinstall "Development Tools" -y\
	    && yum install -y ibffi openssl-devel\
	    && pip3 install virtualenv\
	    && export VIRTUAL_ENV=/src/venv\
	    && python3 -m venv $${VIRTUAL_ENV}\
	    && export PATH="$${VIRTUAL_ENV}/bin:$${PATH}"\
	    && pip3 install --upgrade pip\
	    && pip3 install --upgrade --force -r requirements.txt -t .''' \
	  && rm -rf build/venv

clean:
	@rm -rf enum*; find . -name '*.so' -delete; rm -rf build

debug:
	@ls build/; find . -name '*.so'

.PHONY: all
