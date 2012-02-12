#include <ft2build.h>
#include FT_FREETYPE_H

#define WIDTH 100
#define HEIGHT 60


static const char *letters = "0123456789";

int
main (int argc, char **argv)
{
	int q, w, ch, ox;

	FT_Library library;
	FT_Face face;
	FT_Bitmap bits;

	FT_Init_FreeType (&library);
	FT_New_Face (library, "./arial.ttf", 0, &face);

	printf("static const char letters[] = \"%s\";\n", letters);

	fprintf (stderr, "Found %d faces\n", (int)face->num_faces);
	FT_Set_Char_Size (face, 0, HEIGHT * 64, 0, 72);
	for (ch = 0; letters[ch]; ch++)
	{
		FT_Load_Glyph (face, FT_Get_Char_Index (face, letters[ch]), 0);
		FT_Render_Glyph (face->glyph, FT_RENDER_MODE_NORMAL);
		bits = face->glyph->bitmap;
		ox = (WIDTH - bits.width) / 2;
		fprintf (stderr, "size: %dx%d\n", bits.width, bits.rows, ox);

		int row_skip = 0;
		printf("static int8_t lt%d[] = ", ch);
		char prefix = '{';
		for (w = 0; w < bits.rows; w++)
		{
			int r = face->glyph->bitmap_left, i;
			for (i = 0; i < bits.width; i++) {
				int px = bits.buffer[bits.pitch * w + i];
				if (px) {
					if (r) {
						printf("%c-%d", prefix, r);
						prefix = ',';
						r = 0;
					}
					printf("%c%d",prefix, (px >> 4) ^ 0xf);
					prefix = ',';
				} else {
					r++;
				}
			}
			printf("%c-100", prefix);
		}
		printf("%c-101};\n", prefix);
	}

	printf("static int8_t *lt[] = ");
	for (ch = 0; letters[ch]; ch++)
		printf("%clt%d", ch ? ',' : '{', ch);
	printf("};\n");

	return 1;
}
