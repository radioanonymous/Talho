# -*- coding: utf-8 -*-

import os
from misc import _

def main(bot, args):
    """установить уровень баттхёрта в диджейке (в процентах)."""
    try:
        bhlev = int(args[0])
    except ValueError:
        return
    if bhlev < 0 or bhlev > 100:
        return

    bhpage = open('/home/eurekafag/data/www/radioanon.ru/bhl.php', 'w')

    if bhlev < 50:
        g = 255
	r = bhlev * 5
    else:
        g = 255 - (bhlev - 50) * 5
	r = 255

    bhpage.write('<?php echo "<b><span style=\\"background-color: #333; color: #%02x%02x00; padding: 3px; border: 1px #eee dashed;\\">%d%%</span></b>"; ?>' % (r, g, bhlev))
    bhpage.close()

    return _("установлено.")
        
def info(bot):
    return ((u"bh", u"бх"), 9, main)
