#include <stdio.h>
#include <string>
#include <string.h>
#include "meta-parser.h"

/* Construct title based on actual filename */
static std::string
fname2title(const char *fname)
{
	const char *p = strrchr(fname, '/');
	if (p)
		p++;
	else
		p = fname;
	if (memcmp(p, "vk-", 3) == 0)
		return p + 3;
	if (memcmp(p, "rg-", 3) == 0)
		return p + 3;
	return p;
}

#ifndef NO_META_PARSER
/*****************************************************************/
/*                    Metadata parser enabled                    */
/*****************************************************************/
#include <fcntl.h>
#include <unistd.h>
#include <magic.h>
#include <tag.h>
#include <tfilestream.h>
#include <mpegfile.h>
#include <mp4file.h>
#include <vorbisfile.h>
#include <flacfile.h>
#include <id3v2framefactory.h>
#include "chardet.h"


/* Shifted file stream - a regular filestream that "hides" shift bytes from its beginning.
 * Needed because some files contain fake ID3v2 record at the beginning */
class ShiftedFileStream : public TagLib::FileStream {
private:
	unsigned shift;
public:
	ShiftedFileStream(TagLib::FileName file, unsigned offset = 0) : TagLib::FileStream(file, true), shift(offset) {}

	void seek(long offset, Position p = Beginning) {
		if (p == Beginning)
			TagLib::FileStream::seek(offset + shift, p);
		else
			TagLib::FileStream::seek(offset, p);
	}

	long tell() const {
		return TagLib::FileStream::tell() - shift;
	}
};

/* Global libmagic handle used to detect mime type */
static magic_t mh;

/* Initialize libmagic */
bool
meta_init()
{
	mh = magic_open(MAGIC_SYMLINK | MAGIC_MIME_TYPE);
	if (!mh) {
		fprintf(stderr, "Fatal: unable to create libmagic handle\n");
		return false;
	}

	if (magic_load(mh, NULL) != 0) {
		fprintf(stderr, "Fatal: unable to load libmagic database\n");
		return false;
	}
	return true;
}

/* Shutdown libmagic */
void
meta_cleanup()
{
	if (mh)
		magic_close(mh);
}

static std::string
tag2name(TagLib::Tag *tag)
{
	return tag->artist().to8Bit(false) + " - " + tag->title().to8Bit(true);
}

/* Read portion of file beginning */
static int
read_hdr(const char *fname, char *buf, unsigned bufsz)
{
	int fd = open(fname, O_RDONLY);
	if (fd != -1) {
		int bytes = read(fd, buf, bufsz);
		close(fd);
		return bytes;
	}
	return -1;
}

static std::string
tls2a(const TagLib::String &s)
{
	if (s.isAscii())
		return s.to8Bit(false);
	if (s.isLatin1())
		return auto_recode(s.to8Bit(false).c_str());
	return auto_recode(s.to8Bit(true).c_str());
}

/* Detect file type with libmagic, then extract tags with taglib */
std::string
meta_parse(const char *fname, std::string *mime)
{
	if (mh) {
		int len;
		std::string name;
		const char *ext = NULL;
		char buf[4096];
		const char *ctt = NULL;
		TagLib::File *f = NULL;
		TagLib::IOStream *s = NULL;
		
		len = read_hdr(fname, buf, sizeof(buf));
		if (len < 10)
			goto fallback;

		ctt = magic_buffer(mh, buf, len);

		if (!ctt)
			goto fallback;

		/* Create TagLib::File object */
		if (strcmp(ctt, "audio/mpeg") == 0) {
			int i;
			static const char id3_sig[] = {'I', 'D', '3', 3};
			/* Try to find second signature */
			for (i = 1; i < len - sizeof(id3_sig); i++)
				if (memcmp(buf + i, id3_sig, sizeof(id3_sig)) == 0) {
					s = new ShiftedFileStream(fname, i);
					break;
				}
			if (!s)
				s = new TagLib::FileStream(fname, true);

			f = new TagLib::MPEG::File(s, TagLib::ID3v2::FrameFactory::instance(), false);
			ext = ".mp3";
		} else if (strcmp(ctt, "application/ogg") == 0) {
			/* TODO: distinguish between ogg/flac, ogg/vorbis and ogg/speex */
			f = new TagLib::Ogg::Vorbis::File(fname, false);
			ext = ".ogg";
		} else if (strcmp(ctt, "audio/x-flac") == 0) {
			f = new TagLib::FLAC::File(fname, false);
			ext = ".flac";
		} else if (strcmp(ctt, "audio/mp4") == 0) {
			f = new TagLib::MP4::File(fname, false);
			ext = ".m4a";
		}

		/* Construct name from tags */
		if (f && f->tag()) {
			TagLib::Tag *t = f->tag();

			if (!t->artist().isEmpty())
				name = tls2a(t->artist());

			if (!t->title().isEmpty()) {
				name += " - ";
				name += tls2a(t->title());
			}

			if (!name.empty())
				name += ext;
		}

		delete f;
		delete s;

		if (!name.empty())
			return name;
	}

fallback:
	/* When libmagic is missing don't try to parse any tags */
	if (mime)
		*mime = "audio/mpeg";
	return fname2title(fname);
}

#else
/*****************************************************************/
/*                   Metadata parser disabled                    */
/*****************************************************************/

bool
meta_init()
{
	return true;
}


void
meta_cleanup()
{
}

std::string
meta_parse(const char *fname, std::string *mime)
{
	if (mime)
		*mime = "audio/mpeg";
	return fname2title(fname);
}
#endif

#if 0
int main(int argc, char **argv)
{
	int i;
	meta_init();

	for (i = 1; i < argc; i++) {
		printf("%s -> %s\n",
				argv[i],
				meta_parse(argv[i]).c_str());
	}

	meta_cleanup();
	return 0;
}
#endif
