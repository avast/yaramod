==========
Deployment
==========

A new version of Yaramod is released performing the following steps:

* Open ``include/yaramod/yaramod.h`` and update ``YARAMOD_VERSION_PATCH`` (with big changes we also increment ``YARAMOD_VERSION_MINOR`` and set ``YARAMOD_VERSION_PATCH`` to 0).
* Open ``docs/rtd/conf.py`` and update version in ``release =``.
* Commit and push the changes with message ``"Release v<?>.<?>.<?>"``.
* Create a GitHub release for the new version, autogenerate the release notes, and publish the release.
