#ifndef DARLING_EMULATION_FILEID_CACHE_H
#define DARLING_EMULATION_FILEID_CACHE_H

// The paths of objects this process recently looked up, by device and inode: what fsgetpath() answers first, so that
// it seldom has to search a file system. stat(), lstat(), fstatat() and getattrlist() (for a file ID) note what they
// found; a lookup checks that the path still names that object.

// notes that the absolute Linux path names the object (dev, ino), dev as the 32 bits statfs()'s f_fsid and ATTR_CMN_FSID
// have; paths too long to keep are skipped
void fileid_cache_note(unsigned long long dev, unsigned long long ino, const char* linux_path);

// the absolute Linux path last noted for (dev, ino) into linux_path (size bytes), if it still names that object
// (not following a symlink at its end): 1, or 0
int fileid_cache_find(unsigned long long dev, unsigned long long ino, char* linux_path, unsigned long size);

// that (dev, ino) was found not to be there, for a while (a note of it forgets that)
void fileid_cache_note_absent(unsigned long long dev, unsigned long long ino);
int fileid_cache_absent(unsigned long long dev, unsigned long long ino);

#endif // DARLING_EMULATION_FILEID_CACHE_H
