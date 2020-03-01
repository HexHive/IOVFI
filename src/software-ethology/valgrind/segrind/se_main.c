
/*--------------------------------------------------------------------*/
/*--- SEgrind: The Software Ethology Tool.               se_main.c ---*/
/*--------------------------------------------------------------------*/

/*

   Copyright (C) 2020 Derrick McKee
      derrick@geth.systems

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

static void se_post_clo_init(void)
{
}

static
IRSB* se_instrument ( VgCallbackClosure* closure,
                      IRSB* bb,
                      const VexGuestLayout* layout, 
                      const VexGuestExtents* vge,
                      const VexArchInfo* archinfo_host,
                      IRType gWordTy, IRType hWordTy )
{
    return bb;
}

static void se_fini(Int exitcode)
{
}

static void se_pre_clo_init(void)
{
   VG_(details_name)            ("Software Ethology");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("The binary analysis tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2020, and GNU GPL'd, by Derrick McKee.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(details_avg_translation_sizeB) ( 275 );

   VG_(basic_tool_funcs)        (se_post_clo_init,
                                 se_instrument,
                                 se_fini);

   /* No needs, no core events to track */
}

VG_DETERMINE_INTERFACE_VERSION(se_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
