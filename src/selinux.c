/* selinux - core functions for maintaining SELinux labelking
   Copyright (C) 2012 Red Hat, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Daniel Walsh <dwalsh@redhat.com> */

#include <config.h>
#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/context.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "selinux.h"

#include "error.h"
#include "system.h"
#include "fts.h"

/*
  This function has being added to libselinux-2.1.12-5, but is here
  for support with older versions of SELinux

  Translates a mode into an Internal SELinux security_class definition.
  Returns 0 on failure, with errno set to EINVAL.
*/
static security_class_t mode_to_security_class(mode_t m) {

  if (S_ISREG(m))
    return string_to_security_class("file");
  if (S_ISDIR(m))
    return string_to_security_class("dir");
  if (S_ISCHR(m))
    return string_to_security_class("chr_file");
  if (S_ISBLK(m))
    return string_to_security_class("blk_file");
  if (S_ISFIFO(m))
    return string_to_security_class("fifo_file");
  if (S_ISLNK(m))
    return string_to_security_class("lnk_file");
  if (S_ISSOCK(m))
    return string_to_security_class("sock_file");

  errno=EINVAL;
  return 0;
}

/*
  This function takes a path and a mode and then asks SELinux what the label
  of the path object would be if the current process label created it.
  it then returns the label.

  Returns -1 on failure. errno will be set approptiately.
*/

static int computecon(char const *path, mode_t mode, security_context_t *con) {
  security_context_t scon = NULL;
  security_context_t tcon = NULL;
  security_class_t tclass;
  int rc = -1;

  char *dir = strdup(path);
  if (!dir)
    goto quit;
  if (getcon(&scon) < 0)
    goto quit;
  if (getfilecon(dirname((char *) dir), &tcon) < 0)
    goto quit;
  tclass = mode_to_security_class(mode);
  if (!tclass)
    goto quit;
  rc = security_compute_create(scon, tcon, tclass, con);

quit:
  free(dir);
  freecon(scon);
  freecon(tcon);
  return rc;
}

/*
  This function takes a path and a mode, it asks calls computecon to get the
  label of the path object if the current process created it, then it calls
  matchpathcon to get the default type for the object.  It substitutes the
  default type into label.  It tells the SELinux Kernel to label all new file
  system objects created by the current process with this label.

  Returns -1 on failure. errno will be set approptiately.
*/
int defaultcon (char const *path, mode_t mode) {
  int rc = -1;
  security_context_t scon = NULL, tcon = NULL;
  context_t scontext = NULL, tcontext = NULL;

  rc = matchpathcon(path, mode,  &scon);
  if (rc < 0)
    goto quit;
  rc = computecon(path, mode,  &tcon);
  if (rc < 0)
    goto quit;
  scontext = context_new(scon);
  rc = -1;
  if (!scontext)
    goto quit;
  tcontext = context_new(tcon);
  if (!tcontext)
    goto quit;

  context_type_set(tcontext, context_type_get(scontext));
  rc = setfscreatecon (context_str(tcontext));

//  printf("defaultcon %s %s\n", path, context_str(tcontext));
quit:
  if (scontext)
    context_free(scontext);
  if (scontext)
    context_free(tcontext);
  freecon(scon);
  freecon(tcon);
  return rc;
}

/*
  This function takes a path of an existing file system object, and a boolean
  that indicates whether the function should preserve the objects label or
  generate a new label using matchpathcon.  If the function
  is called with preserve, it will ask the SELinux Kernel what the default label
  for all objects created should be and then sets the label on the object.
  Otherwise it calls matchpathcon on the object to ask the system what the
  default label should be, extracts the type field and then modifies the file
  system object.

  Returns -1 on failure. errno will be set approptiately.
*/
static int restorecon_private (char const *path, bool preserve) {
  int rc = -1;
  struct stat sb;
  security_context_t scon = NULL, tcon = NULL;
  context_t scontext = NULL, tcontext = NULL;
  int fd;

  if (preserve) {
    if (getfscreatecon (&tcon) < 0)
      return rc;
    rc = lsetfilecon (path, tcon);
    freecon(tcon);
    return rc;
  }

  fd = open (path, O_RDONLY | O_NOFOLLOW);
  if (!fd && (errno != ELOOP))
    goto quit;

  if (fd) {
    rc = fstat (fd, &sb);
    if (rc < 0)
      goto quit;
  } else {
    rc = lstat (path, &sb);
    if (rc < 0)
      goto quit;
  }

  rc = matchpathcon(path, sb.st_mode,  &scon);
  if (rc < 0)
    goto quit;
  scontext = context_new(scon);
  rc = -1;
  if (!scontext)
    goto quit;

  if (fd) {
    rc = fgetfilecon (fd, &tcon);
    if (!rc)
      goto quit;
  } else  {
    rc = lgetfilecon (path, &tcon);
    if (!rc)
      goto quit;
  }
  tcontext = context_new(tcon);
  if (!tcontext)
    goto quit;

  context_type_set(tcontext, context_type_get(scontext));

  if (fd)
        rc = fsetfilecon (fd, context_str(tcontext));
  else
        rc = lsetfilecon (path, context_str(tcontext));

//  printf("restorcon %s %s\n", path, context_str(tcontext));
quit:
  close(fd);
  if (scontext)
    context_free(scontext);
  if (scontext)
    context_free(tcontext);
  freecon(scon);
  freecon(tcon);
  return rc;
}

/*
  This function takes three parameters:
  Path of an existing file system object.
  A boolean indicating whether it should call restorecon_private recursively
  or not.
  A boolean that indicates whether the function should preserve the objects
  label or generate a new label using matchpathcon.

  If Recurse is selected and the file system object is a directory, restorecon
  calls restorecon_private on every file system object in the directory.

  Returns false on failure. errno will be set approptiately.
*/
bool restorecon (char const *path, bool recurse, bool preserve) {
  const char *mypath[2] = { path, NULL };
  FTS *fts;
  bool ok = true;

  if (!recurse)
    return restorecon_private(path, preserve);

  fts = fts_open ((char *const *)mypath, FTS_PHYSICAL, NULL);
  while (1)
    {
      FTSENT *ent;

      ent = fts_read (fts);
      if (ent == NULL)
        {
          if (errno != 0)
            {
              /* FIXME: try to give a better message  */
              error (0, errno, _("fts_read failed"));
              ok = false;
            }
          break;
        }

      ok &= restorecon_private(fts->fts_path, preserve);
    }

  if (fts_close (fts) != 0)
    {
      error (0, errno, _("fts_close failed"));
      ok = false;
    }

  return ok;
}
