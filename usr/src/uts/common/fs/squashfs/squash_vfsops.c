#include <sys/stddef.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dirent.h>

#include <sys/modctl.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>

#include <sys/cmn_err.h>

#include <sys/policy.h>
#include <sys/atomic.h>
#include <sys/time.h>
#include <sys/zmod.h>

extern struct mod_ops mod_fsops;
static int squashfsinit(int, char *);
struct vnodeops *squashfs_fvnodeops;
struct vnodeops *squashfs_dvnodeops;

uint32_t pow2(uint32_t a) {
	uint32_t x = 1;
	while(a-- > 0) {
		x <<= 1;
	}
	return x;
}

static int squashfs_type;

static major_t squashfs_major;
static minor_t squashfs_minor;
static kmutex_t	squashfs_minor_lock;

static uint32_t squashfs_mount_count = 0;

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"squashfs",
	squashfsinit,
	VSW_CANLOFI | VSW_MOUNTDEV,
	NULL
};

static struct modlfs modlfs = {
	&mod_fsops,
	"SquashFS Compressed Filesystem",
	&vfw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlfs,
	NULL
}; 

int
_init(void) {
	int error;
	error = mod_install(&modlinkage);
	return (error);
}

int
_fini(void) {
	int error;	
	error = mod_remove(&modlinkage);
	if( error )
		return (error);

	if( squashfs_mount_count > 0 )
		return (EBUSY);

	mutex_destroy(&squashfs_minor_lock);
	(void) vfs_freevfsops_by_type(squashfs_type);
	vn_freevnodeops(squashfs_fvnodeops);
	vn_freevnodeops(squashfs_dvnodeops);

	return (0);

}

int
_info(struct modinfo *modinfop) {

	return (mod_info(&modlinkage, modinfop));
}


// Such reference: https://dr-emann.github.io/squashfs/#superblock

/// flags
#define SQ_FL_UNCOMPRESSED_INODES 		0x0001
#define SQ_FL_UNCOMPRESSED_DATA			0x0002
#define SQ_FL_CHECK						0x0004 	//should always be unset
#define SQ_FL_UNCOMPRESSED_FRAGMENTS 	0x0008
#define SQ_FL_NO_FRAGMENTS 				0x0010
#define SQ_FL_ALWAYS_FRAGMENTS 			0x0020
#define SQ_FL_DUPLICATES 				0x0040
#define SQ_FL_EXPORTABLE				0x0080 
#define SQ_FL_UNCOMPRESSED_XATTRS		0x0100
#define SQ_FL_NO_XATTRS 				0x0200
#define SQ_FL_COMPRESSOR_OPTIONS		0x0400
#define SQ_FL_UNCOMPRESSED_IDS 			0x0800

/// compression types
#define SQ_COMP_NONE 	0
#define SQ_COMP_GZIP 	1
#define SQ_COMP_LZMA 	2
#define SQ_COMP_LZO		3
#define SQ_COMP_XZ 		4
#define SQ_COMP_LZ4 	5
#define SQ_COMP_ZSTD 	6
#define SQ_COMP_MAX 	SQ_COMP_GZIP


#define SQ_MAGIC 0x73717368

/// superblock structure
struct squashfs_superblock {
	uint32_t 	magic;
	uint32_t 	inode_count;
	int32_t		modification_time;
	uint32_t 	block_size;
	uint32_t	fragment_entry_count;
	uint16_t	compression_id;
	uint16_t	block_log;							// the log(2) of block_size
	uint16_t	flags;
	uint16_t	id_count;
	uint16_t	version_major;
	uint16_t	version_minor;
	uint64_t	root_inode_ref;
	uint64_t 	bytes_used;
	uint64_t	id_table_start;
	uint64_t	xattr_id_table_start;
	uint64_t	inode_table_start;
	uint64_t	directory_table_start;
	uint64_t	fragment_table_start;
	uint64_t	export_table_start;
};


#define SQ_TYPE_DIR 		1
#define SQ_TYPE_FILE 		2
#define SQ_TYPE_SYMLINK	3
#define SQ_TYPE_BLKDEV	4
#define SQ_TYPE_CHARDEV 5
#define SQ_TYPE_FIFO		6
#define SQ_TYPE_SOCKET	7
#define SQ_TYPE_MAX			SQ_TYPE_SOCKET

struct squashfs_inode {
	uint16_t 	inode_type;
	uint16_t	permissions;
	uint16_t	uid_idx;
	uint16_t	gid_idx;
	uint32_t	modified_time;
	uint32_t	inode_number;
};

struct squashfs_handle {
	struct vfs 	*p_vfs;
	struct vnode 	*p_mountpoint;
	struct vnode	*p_special;
	struct vnode	*p_rootnode;
	struct vnode	*p_devvn;
	int devvn_open;
	dev_t		sq_dev; 	// device created for this mount
	dev_t 		xdev;		// block device holding the squashfs image
	kmutex_t 	lock;
	struct squashfs_superblock superblock;
};

/* 
	implements some sanity checks on the SquashFS superblock during the mount -
	
	returns 0 if it all looks OK
	
	returns an errno either "not supported" ENOTSUP or EINVAL if the on disk format 
			appears to be corrupt
*/
int squashfs_check_superblock( struct squashfs_superblock* superblock ) {	
	// check the magic
	if( superblock->magic != SQ_MAGIC ) {
		cmn_err(CE_WARN, "SquashFS Superblock magic '%x' doesn't match '%x'", superblock->magic, SQ_MAGIC);
		return EINVAL;
	}

	// cmn_err(CE_WARN, "SquashFS: image has %d inodes", superblock->inode_count);
	// cmn_err(CE_WARN, "SquashFS: image was last modified at %d", superblock->modification_time);
	// cmn_err(CE_WARN, "SquashFS: image has block size of %d", superblock->block_size);
	// cmn_err(CE_WARN, "SquashFS: image has %d fragments", superblock->fragment_entry_count);

	// check that we support the compression type
	if( superblock->compression_id > SQ_COMP_MAX ) {
		cmn_err(CE_WARN, "SquashFS: Unsupported compression %d", superblock->compression_id);
	 	return (ENOTSUP);
	}

	// // check the block_log is the log2(block_size)
	if( pow2(superblock->block_log) != superblock->block_size ) {
	 	cmn_err(CE_WARN, "SquashFS: invalid filesystem - block_log (%d) is not valid for block size %d",superblock->block_log, superblock->block_size);
	 	return (EINVAL);	
	}

	// check the unset flag is .. unset
	if( (superblock->flags & SQ_FL_CHECK) != 0x0 ) {
	 	cmn_err(CE_WARN, "SquashFS: invalid filesystem - check flag is set");
	 	return (EINVAL);	
	}

	if( superblock->version_major != 4 && superblock->version_minor != 0 ) {
	 	cmn_err(CE_WARN, "SquashFS: invalid filesystem - only version 4.0 is supported (%d.%d in image)", superblock->version_major, superblock->version_minor);
	 	return (ENOTSUP);		
	}
	// check that all the tables are in the order we expect!!
	if( superblock->inode_table_start >= superblock->directory_table_start) {
		cmn_err(CE_WARN, "SquashFS: Expected inode table to precede the directory table");
		return (ENOTSUP);
	}
	if( superblock->directory_table_start >= superblock->fragment_table_start) {
		cmn_err(CE_WARN, "SquashFS: Expected directory table to precede the fragment table");
		return (ENOTSUP);
	}
	if( superblock->fragment_table_start >= superblock->export_table_start) {
		cmn_err(CE_WARN, "SquashFS: Expected inode table to precede the directory table");
		return (ENOTSUP);
	}
	if( superblock->export_table_start >= superblock->id_table_start) {
		cmn_err(CE_WARN, "SquashFS: Expected ID table to precece the export table");
	}
	// My test file had xattr 0xFFFFF... out. 
	// if( superblock->id_table_start >= superblock->xattr_idtable_start) {
		// cmn_err(CE_WARN, "SquashFS: Expected ID table to precece the export table");
	// }
	return 0;
}


inline void squashfs_parse_inode(uint64_t inode, uint32_t* metadata_block_index, uint16_t *inode_offset) {
	if( metadata_block_index ) *metadata_block_index = (inode >> 16) & 0xFFFFFFFF;
	if( inode_offset ) *inode_offset = inode & 0xFFFF;
}


int squashfs_back_read(struct squashfs_handle* handle, offset_t offset, size_t size, void* dest) {
	int block = offset / 512;
	int initial_offset = offset % 512;
	int error;
	int copy_amount = 0;
	unsigned char *b;
	offset_t output_offset = 0;

	while( size > 0 ) {
		buf_t *buffer = BREAD(handle->p_devvn->v_rdev, block++, 512);
		error = geterror(buffer);
		if( error ) {
			brelse(buffer);
			return error;
		}

		if( buffer->b_bufsize < initial_offset + 1 ) {
			brelse(buffer);
			return EIO;
		}
		copy_amount = size;

		b =  (unsigned char*)buffer->b_un.b_addr;

		if( buffer->b_bufsize < 512 ) {
			brelse(buffer);
			return EIO;
		}

		copy_amount = 512 - initial_offset;
		if( size < copy_amount )
			copy_amount = size;

		memcpy(dest + output_offset, buffer->b_un.b_addr+initial_offset,copy_amount);
		b = (unsigned char*) (dest + output_offset);

		size -= copy_amount;
		output_offset+= copy_amount;
		initial_offset = 0;
		
		brelse(buffer);
	}
	
	b = (unsigned char*) dest;
	return 0;
}

int squashfs_load_inode(struct squashfs_handle* handle, uint64_t inode_ref, struct squashfs_inode* inode) {
	int error = 0;

	// decompose the inode reference into the metadata block offset and internal offset
	uint32_t external_offset;
	uint16_t internal_offset;
	uint16_t compressed_size;

	squashfs_parse_inode(inode_ref, &external_offset, &internal_offset);

	// now, let's load the block!
	uint64_t read_offset = handle->superblock.inode_table_start + external_offset;
	if( read_offset >= handle->superblock.directory_table_start) {
		return EINVAL;
	}

	// read in the compressed block size
	error = squashfs_back_read(handle, read_offset, sizeof(uint16_t), &compressed_size);
	read_offset += sizeof(uint16_t);
	if( error ) { 
		return error;
	}

	if( read_offset + compressed_size > handle->superblock.directory_table_start) {
		return EINVAL;
	}
	
	// OK! load in the block!
	uint8_t compressed[8192], buffer[8192];
	size_t block_size = sizeof(buffer);
	error = squashfs_back_read(handle, read_offset, compressed_size, compressed);
	if( error ) {
		return error;
	}
	
	error = z_uncompress(buffer, &block_size, compressed, compressed_size);
	if( error != Z_OK ) {
		cmn_err(CE_WARN, "SquashFS: Failed to decompress metadata block at offset %ld (%d)", read_offset, error);
		return EINVAL;
	}

	// woop, have a buffer!
	if(inode) {
		memcpy(inode, buffer, sizeof(struct squashfs_inode));
	}

	return 0;
}


// setup any resources we expect to exist for the lifetime of the handle
int squashfs_alloc_handle(struct squashfs_handle** handle) {
  *handle = kmem_zalloc(sizeof (struct squashfs_handle), KM_NORMALPRI | KM_NOSLEEP);
  if( *handle == NULL ) {
  	return (ENOMEM);
  }
  mutex_init(&(*handle)->lock, NULL, MUTEX_DEFAULT, NULL);
  return 0;
}

// releases any active resources in the handle structure
// doesn't release the acutal handle
void squashfs_free_handle(struct squashfs_handle** handle_p) { 

	if( *handle_p == NULL ) 
		return;

	struct squashfs_handle *handle = *handle_p;

	if( handle->p_devvn ) {
		if( handle->devvn_open ) { VOP_CLOSE(handle->p_devvn, FREAD, 1, (offset_t)0, NULL, NULL); handle->devvn_open = 0; }
		VN_RELE(handle->p_devvn); handle->p_devvn = NULL;
	}
	
	if( handle->p_rootnode ) { VN_RELE(handle->p_rootnode); handle->p_rootnode = NULL; }
	if( handle->p_devvn ) { VN_RELE(handle->p_devvn); handle->p_devvn = NULL; }

	mutex_destroy(&handle->lock);
	kmem_free(*handle_p, sizeof(struct squashfs_handle) );
	*handle_p = NULL;
}



// does the work t resolve the mount arguments into a dev_t structure that we'll call to access
// the underlying SquashFS image. It needs to consider if there is a lofi device created by the 
// vfs layer, or if we're talking directly to a device special.
//
// for testing each code path, it seems that mount <some file> <mountpoint> will create a lofi
// device mapped to <some file>, and vfs_get_lofi will return the vnode pointer
//
// if you lofiadm -a <some file> and then mount the /dev/lofi/<id> then this lofi isn't bound
// to the filesystem and tests the alternate path, whilst still using the same underlying image
//
int squashfs_resolve_device(struct vfs *vfsp, struct mounta *mounta, struct cred *cr, dev_t *dev) {
	struct vnode *lvp = NULL;
	int error;

	// get_lofi returns -1 when there is no lofi, 0 on OK, +ve on error
  error = vfs_get_lofi(vfsp, &lvp);

  if( error > 0 ) {
  	return error;
  } else if( error == 0 ) {
  	cmn_err(CE_WARN, "Using lofi device");
  	// got a lofi device
  	*dev = lvp->v_rdev;
 		
  } else {
  	// lvp is NULL here
  	cmn_err(CE_WARN, "No LOFI, using special");

  	// no associated lofi device, let's lookup the special and use that
  	struct pathname special;
		error = pn_get(mounta->spec, UIO_USERSPACE, &special);

		if( error ) {
			pn_free(&special);
			return (error);
		}
		
		error = lookupname(special.pn_path, UIO_SYSSPACE, FOLLOW, NULLVPP, &lvp);
		pn_free(&special);
		if( error ) {
			return error;
		}

		*dev = lvp->v_rdev;
  }

  	// before we release it, do a sanity check on whichever device we're talking to
  	if( lvp->v_type != VBLK ){
  		VN_RELE(lvp);
  		return ENOTBLK;
	}

  	// check that we can open this device
	error = secpolicy_spec_open(cr, lvp, FREAD);
	if (error) {
		VN_RELE(lvp);
		return error;
	}

	// can we read the device?
	error = VOP_ACCESS(lvp, VREAD, 0, cr, NULL);
	// we're done with the VFS pointer to the device now.
	VN_RELE(lvp); lvp = NULL;
	if( error ) {
		return error;
	}

	// is the device already mounted?
	if (vfs_devismounted(*dev)) {
		return EBUSY;
	}
	
	return 0;
}

static int squashfs_mount(struct vfs *vfsp, struct vnode *mount_point, struct mounta *mounta, struct cred * cr ) {
	int error;
	buf_t *superblock_buffer = NULL;
	buf_t *inode_block = NULL;

	if( mount_point->v_type != VDIR) {
		error = ENOTDIR;
		goto error;
	}

	if (secpolicy_fs_mount(cr, mount_point, vfsp) != 0) {
		error = EPERM;
		goto error;
	}

	struct squashfs_handle* fsp;
	error = squashfs_alloc_handle(&fsp);
	if( error ) {
		goto error;
	}

	/* find a free minor number for this mount */
	if(squashfs_major) {
		mutex_enter(&squashfs_minor_lock);
		do {
			squashfs_minor++;
			fsp->sq_dev = makedevice(squashfs_major, squashfs_minor);
		} while (vfs_devismounted(fsp->sq_dev));
		mutex_exit(&squashfs_minor_lock);

		vfsp->vfs_dev = fsp->sq_dev;
		vfs_make_fsid(&vfsp->vfs_fsid, fsp->sq_dev, squashfs_type);
	}

	// resolve and check the device backing the mount
	error = squashfs_resolve_device( vfsp, mounta, cr, &fsp->xdev);
	if( error ) {
		goto error;
	}
	
	fsp->p_devvn = makespecvp(fsp->xdev, VBLK);
	if( fsp->p_devvn == NULL ) {
		error = EIO;
		goto error;
	}
	if(IS_SWAPVP(fsp->p_devvn)) {
		error = EBUSY;
		goto error;
	}

	vfsp->vfs_data = fsp;
	vfsp->vfs_fstype = squashfs_type;
	vfsp->vfs_bsize = PAGESIZE;
	vfsp->vfs_flag |= VFS_RDONLY | VFS_NOTRUNC;
	
	fsp->p_vfs = vfsp;
	fsp->p_mountpoint = mount_point;
	
	error = VOP_OPEN(&fsp->p_devvn, FREAD, cr, NULL);
	if( error ) {
		VN_RELE(fsp->p_devvn);
		return (error);
	}
	fsp->devvn_open = 1;

	// read in and sanity check the superblock
	superblock_buffer = bread(fsp->p_devvn->v_rdev, 0, sizeof(struct squashfs_superblock));
	error = geterror(superblock_buffer);
	if( error ) { 
		goto error;
	}
	if( superblock_buffer->b_bufsize < sizeof(struct squashfs_superblock)) {
		error = EINVAL;
		goto error;
	}

	// copy the superblock into our FS handle
	memcpy(&fsp->superblock, superblock_buffer->b_un.b_addr, sizeof(struct squashfs_superblock));
	brelse(superblock_buffer); superblock_buffer = NULL;

	// sanity check the superblock
	error = squashfs_check_superblock(&fsp->superblock);
	if( error ) {
		goto error;
	}	


	// load in the root inode!
	struct squashfs_inode inode;
	error = squashfs_load_inode(fsp, fsp->superblock.root_inode_ref, &inode);
	if( error ) {
		goto error;
	}

	cmn_err(CE_WARN, "Loaded the root inode type = %d!", inode.inode_type);

	fsp->p_rootnode = vn_alloc(KM_NORMALPRI | KM_NOSLEEP);
	if( fsp->p_rootnode == NULL ) {
		error = ENOMEM;
		goto error;
	}
	fsp->p_rootnode->v_vfsp = vfsp;
	fsp->p_rootnode->v_data = (void*)0x12345678;
	vn_setops(fsp->p_rootnode, squashfs_dvnodeops);
 	fsp->p_rootnode->v_type = VDIR;
	fsp->p_rootnode->v_flag |= VROOT | VNOCACHE | VNOMAP | VNOSWAP | VNOMOUNT;

	cmn_err(CE_WARN, "Root node reference count is %d", fsp->p_rootnode->v_count);

	atomic_inc_32(&squashfs_mount_count);
	return (0);

error: 
	if( superblock_buffer ) { brelse(superblock_buffer); superblock_buffer = NULL;}
	if( inode_block ) { brelse(inode_block); inode_block = NULL; }
	squashfs_free_handle(&fsp);	
	return (error);
}

static int squashfs_root(vfs_t *vfsp, vnode_t **vpp) {
	struct squashfs_handle* fsp = (struct squashfs_handle*)vfsp->vfs_data;
	*vpp = fsp->p_rootnode; 
	VN_HOLD(*vpp);
	return (0);
}

static int squashfs_unmount(struct vfs *vfsp, int flag, struct cred * cr ) {

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	struct squashfs_handle* fsp = (struct squashfs_handle*)vfsp->vfs_data;
	cmn_err(CE_WARN, "unmount ref count = %d", fsp->p_rootnode->v_count);

	if( fsp -> devvn_open )
		VOP_CLOSE(fsp->p_devvn, FREAD, 1, (offset_t)0, cr, NULL);
	fsp->devvn_open = 0;

	VN_RELE(fsp->p_rootnode);
	fsp->p_rootnode = NULL;

	squashfs_free_handle((struct squashfs_handle**)&vfsp->vfs_data);
	atomic_dec_32(&squashfs_mount_count);

	return (0);
}

static int squashfs_open(struct vnode** vpp, int flag, struct cred *cr, caller_context_t *ct) {
	cmn_err(CE_WARN, "squashfs_open");
	// bump the vnode refcount (and vfs ref count?)
	return (0);
}

static int squashfs_close(struct vnode* vp, int flag, int count, offset_t offset, struct cred *cr, caller_context_t *ct) {
	cmn_err(CE_WARN, "squashfs_close");

	// decrement the vnode (and vfs?) refcount
	return (0);
}

static int squashfs_readdir(vnode_t* vp, struct uio* uiop, cred_t *cr, int *eofp, caller_context_t *ct, int flags) {
	if( vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);
	
	cmn_err(CE_WARN, "readdir offset %lld ", uiop->uio_loffset);

	if( uiop->uio_loffset >= MAXOFF_T ) {
		if(eofp) *eofp = 1;
		return 0;
	}

	if( uiop->uio_iovcnt != 1)
		return (EINVAL);

	if( vp->v_type != VDIR)
		return (ENOTDIR);


	int error = 0;

	ulong_t total_bytes_wanted = uiop->uio_iov->iov_len;
	ulong_t bufsize = total_bytes_wanted + sizeof(struct dirent64);

	void* buffer = kmem_alloc(bufsize, KM_SLEEP);

	struct dirent64 *dp = (struct dirent64*) buffer;

	// let's say we have 10 files called "foobar[0-9]"

	// manually write out 3
	ulong_t offset = 0;
	char name[15];

	ulong_t outcount = 0;

	if( eofp ) *eofp = 0;

	ulong data_offset = 0;

	int printed_first_line = 0;
	for(offset=0;offset < 1000; offset++) {
		sprintf(name, "foobar%03ld", offset);

		size_t namelen = strlen(name);
		size_t reclen = DIRENT64_RECLEN(namelen);

		// skip ahead to the offset we're interested in
		if( data_offset >= uiop->uio_offset ) {
			if( printed_first_line == 0 ){
				cmn_err(CE_WARN, "starting from %s offset=%ld reclen=%ld", name, data_offset, reclen);
				printed_first_line = 1;
			}
			if(outcount + reclen > total_bytes_wanted) {
				if(!outcount)
					error = EINVAL; // buffer was too small for any entries
				goto exit;
			}

			strncpy(dp->d_name, name, DIRENT64_NAMELEN(reclen));
			dp->d_reclen = (ushort_t)reclen;
			dp->d_ino = data_offset;
			dp->d_off = data_offset + 1;
			

			dp = (struct dirent64 *)((uintptr_t)dp + reclen);
			outcount += reclen;
		}

		data_offset += reclen;
	}
	if( eofp ) *eofp = 1;	

exit:
	
	uiop->uio_offset = data_offset;

	if(!error)
		error = uiomove(buffer, outcount, UIO_READ, uiop);

	kmem_free(buffer, bufsize);

	cmn_err(CE_WARN, "readdir returns %d (offset=%lld eofp=%d)", error, uiop->uio_offset, (*eofp));
	return (error);
}

static int squashfs_read(vnode_t* vp, struct uio* uiop, int ioflag, struct cred *cr, struct caller_context *ct) {
	return (ENOMEM);
}


static int squashfs_access(vnode_t* vp, int mode, int flags, struct cred *cr, struct caller_context *ct) {



	if( mode & VWRITE )
		return (EACCES);
	return 0;
}

/*static int squashfs_lookup(vnode_t* vp, char *nm, struct vnode **vpp, struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cr, caller_context_t *ct, int *direntflags, pathname_t *realpnp) {

 	return (ENOMEM);
}
*/
static int squashfs_getattr(vnode_t* vp, vattr_t *vap, int flags, cred_t *cr, caller_context_t *ct) {

	vap->va_type = vp->v_type;
	vap->va_mode = 0755;
	vap->va_uid = 0;
	vap->va_gid = 0;
	vap->va_fsid = 0;
	vap->va_nodeid = 1;
	vap->va_nlink = 2;
	vap->va_size = 1234;
	gethrestime(&vap->va_atime);
	gethrestime(&vap->va_mtime);
	gethrestime(&vap->va_ctime);
	vap->va_blksize = PAGESIZE;
	vap->va_rdev = 0;
	vap->va_seq = 0;

	return (0);
}

const fs_operation_def_t squashfs_vnodeops_template[] = {
	VOPNAME_OPEN,	{ .vop_open = 	squashfs_open },
	VOPNAME_CLOSE,	{ .vop_close = 	squashfs_close },
	VOPNAME_READ,	{ .vop_read = 	squashfs_read },
	VOPNAME_IOCTL, 	{ .error =	fs_error },
	VOPNAME_GETATTR, { .vop_getattr = squashfs_getattr },
	VOPNAME_ACCESS,	{ .vop_access = squashfs_access },
	VOPNAME_LOOKUP,	{ .error = fs_error }, // used to find the DIR given path  //.vop_lookup = squashfs_lookup },
	VOPNAME_READDIR, { .vop_readdir = squashfs_readdir },
	VOPNAME_READLINK, { .error = 	fs_error },
	VOPNAME_FSYNC, 	{ .error = 	fs_error },
	VOPNAME_INACTIVE, { .error = 	fs_error },
	VOPNAME_FID, 	{ .error = 	fs_error },
	VOPNAME_SEEK,	{ .error = 	fs_error },
	VOPNAME_SPACE,	{ .error = 	fs_error },
	VOPNAME_GETPAGE, { .error = 	fs_error },
	VOPNAME_PUTPAGE, { .error = 	fs_error },
	VOPNAME_MAP, 	{ .error = 	fs_error },
	VOPNAME_ADDMAP, { .error = 	fs_error },
	VOPNAME_DELMAP, { .error = 	fs_error },
	VOPNAME_PATHCONF, { .error = 	fs_error },
	VOPNAME_VNEVENT, { .error = 	fs_error },
	NULL,		NULL
};

static int
squashfsinit(int fstype, char *name) 
{
	cmn_err(CE_WARN, "squashfs - init");
	
	static const fs_operation_def_t squashfs_vfsops_template[] = {
		VFSNAME_MOUNT,  	{ .vfs_mount 	= squashfs_mount },
		VFSNAME_UNMOUNT, 	{ .vfs_unmount 	= squashfs_unmount },
		VFSNAME_ROOT, 		{ .vfs_root 	= squashfs_root },
		NULL, 			NULL
	};
	int error;

	error = vfs_setfsops(fstype, squashfs_vfsops_template, NULL);
	if( error != 0 ) {
		cmn_err(CE_WARN, "squashfsinit: bad vfs ops template");
		return (error);
	}

	squashfs_type = fstype;
	squashfs_mount_count = 0;
	cmn_err(CE_WARN, "squashfs fs type is %d", fstype);
	
	error = vn_make_ops("squashfs", squashfs_vnodeops_template, &squashfs_fvnodeops);
	if( error != 0 ) {
		(void) vfs_freevfsops_by_type(fstype);
		return (error);	
	}			
	cmn_err(CE_WARN, "registered file ops");

	error = vn_make_ops("squashfsd", squashfs_vnodeops_template, &squashfs_dvnodeops);
	if( error != 0 ) {
		(void) vfs_freevfsops_by_type(fstype);
		vn_freevnodeops(squashfs_fvnodeops);
		return (error);	
	}
	cmn_err(CE_WARN, "Registered directory ops");

	if ((squashfs_major = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "squashfsinit: Can't get unique device number.");
		squashfs_major = 0;
	}
	mutex_init(&squashfs_minor_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}
