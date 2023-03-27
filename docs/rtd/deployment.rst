==========
Deployment
==========

A new version of Yaramod is released performing the following steps:

* Open ``include/yaramod/yaramod.h`` and update ``YARAMOD_VERSION_PATCH`` (with big changes we also increment ``YARAMOD_VERSION_MINOR`` and set ``YARAMOD_VERSION_PATCH`` to 0).
* Open ``docs/rtd/conf.py`` and update version in ``release =``.
* In ``CHANGELOG.md`` add entry for the new version. List all important changes with links to issues and PRs.
* Commit the changes with message "Release v<?>.<?>.<?>".
* Create a git tag by running ``git tag -a v<?>.<?>.<?> -m "Release v<?>.<?>.<?>"``.
* Push the new tag with ``git push origin v<?>.<?>.<?>``.
* Push the commit after the release to master with ``git push origin master``.
