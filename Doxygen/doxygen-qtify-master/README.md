doxygen-qtify
=============

This is a quick hack for a Doxygen CSS stylesheet which makes the Doxygen output 
look like a normal Qt5 documentation.

> Note: This quick hack does not include all style sheet changes to make every
possible Doxygen output look like Qt docs. It contains only changes to make 
docs for my project look like Qt docs and intergrate nicely into the Qt Help.
Also this does only contain the style sheet, no images, etc.

To make use of the stylesheet, copy it in the directory where your Doxyfile
resides and reference it from the Doxyfile using:

```
# The HTML_EXTRA_STYLESHEET tag can be used to specify an additional user-
# defined cascading style sheet that is included after the standard style sheets
# created by doxygen. Using this option one can overrule certain style aspects.
# This is preferred over using HTML_STYLESHEET since it does not replace the
# standard style sheet and is therefor more robust against future updates.
# Doxygen will copy the style sheet file to the output directory. For an example
# see the documentation.
# This tag requires that the tag GENERATE_HTML is set to YES.

HTML_EXTRA_STYLESHEET  = qtify.css
```

You should also consider to deactivate the tree view. This makes the doxygen
output a better fit into the Qt help system:

```
GENERATE_TREEVIEW      = NO
```

Have fun!


