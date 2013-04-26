# makefile for spw-api-scripts
# uses distutils files etc
# generates changelog first
# tabs have a special meaning in makefiles
# vim: set noet :


# generate source and binary RPMs
rpms:
	git log --format="%cd (%h) %s - %an" --date=short > ChangeLog
	python setup.py bdist_rpm 

# generate tarball
tarball:
	python setup.py sdist

# clean up build files
clean:
	find -type f -name '*.pyo' -o -name '*.pyc' | xargs rm -vf
	rm -rvf build

# clean up RPMs too
distclean: clean
	rm -rvf dist
    
