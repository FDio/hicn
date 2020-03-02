
# Building Documents

These instructions show how documentation sources are built.

To build your files, you can either Create a Virtual Environment using
virtualenv, which installs all the required applications for you.

# Create a Virtual Environment using virtualenv

For more information on how to use the Python virtual environment check
out <https://packaging.python.org/guides/installing-using-pip-and-virtualenv>

# Get the Documents

For example start with a clone of the hicn.

```bash
$ git clone <https://gerrit.fd.io/r/hicn>
$ cd hicn
```

# Install the virtual environment

```bash
$ python3 -m pip install --user virtualenv
$ python3 -m virtualenv env
$ source env/bin/activate
$ pip install -r docs/etc/requirements.txt
$ cd docs
```

Which installs all the required applications into its own, isolated,
virtual environment, so as to not interfere with other builds that may
use different versions of software.

# Build the html files

Be sure you are in your hicn/docs directory, since that is where Sphinx will
look for your conf.py file, and build the documents into an index.html file

```bash
$ make html
```

# View the results

If there are no errors during the build process, you should now have an
index.html file in your hicn/docs/build/html directory, which you can
then view in your browser.
