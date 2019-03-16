# Contributing

When contributing to this repository, please first discuss the change you wish to make via issue,
email, or any other method with the owners of this repository before making a change.

Please note we have a [code of conduct](CODE_OF_CONDUCT.md), please follow it in all your interactions with the project.

## Pull Request Process

1. Ensure all the tests pass
2. Ensure any install or build dependencies are removed
3. Update the README.md with details of changes to the interface(s) and/or examples

## Tests

### generic-provider

    $ sudo pip install venv --user || sudo pip install virtualenv --user

    $ pushd generic_provider

    $ python -m venv venv || python -m virtualenv venv

    $ . venv/bin/activate

    $ pip install -r requirements.txt

    $ python -m unittest

    $ deactivate

    $ popd

### templates

    $ sudo pip install venv --user || sudo pip install virtualenv --user

    $ python -m venv venv || python -m virtualenv venv

    $ . venv/bin/activate

    $ pip install -r requirements.txt

    $ export CFN_STACKS='aws-backup cognito-idp client-vpn vpc-peering'

    $ ./validate-templates.sh

    $ deactivate
