#include <config.h>
#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <argp.h>
#include <assert.h>
#include <ctype.h>
#include <dwarf.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <langinfo.h>
#include <libintl.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "../libelf/libelfP.h"
#include "../libelf/common.h"
#include "../libebl/libeblP.h"
#include "../libdw/libdwP.h"
#include "../libdwfl/libdwflP.h"
#include "../libdw/memory-access.h"

#ifndef likely
# define unlikely(expr) __builtin_expect (!!(expr), 0)
# define likely(expr) __builtin_expect (!!(expr), 1)
#endif

/* Numbers of sections and program headers in the file.  */
static size_t shnum;
static size_t phnum;

/* Declarations of local functions.  */
static PyObject * process_file (int fd, const char *fname, bool only_one);
static PyObject * process_elf_file (Dwfl_Module *dwflmod, int fd);
static PyObject * print_ehdr (Ebl *ebl, GElf_Ehdr *ehdr);
static PyObject * print_symtab (Ebl *ebl, int type);
static PyObject * handle_symtab (Ebl *ebl, Elf_Scn *scn, GElf_Shdr *shdr);


static int
find_no_debuginfo (Dwfl_Module *mod __attribute__ ((unused)),
                   void **userdata __attribute__ ((unused)),
                   const char *modname __attribute__ ((unused)),
                   Dwarf_Addr base __attribute__ ((unused)),
                   const char *file_name __attribute__ ((unused)),
                   const char *debuglink_file __attribute__ ((unused)),
                   GElf_Word debuglink_crc __attribute__ ((unused)),
                   char **debuginfo_file_name __attribute__ ((unused)))
{
  return -1;
}

/* Trivial callback used for checking if we opened an archive.  */
static int
count_dwflmod (Dwfl_Module *dwflmod __attribute__ ((unused)),
               void **userdata __attribute__ ((unused)),
               const char *name __attribute__ ((unused)),
               Dwarf_Addr base __attribute__ ((unused)),
               void *arg)
{
  if (*(bool *) arg) 
    return DWARF_CB_ABORT;
  *(bool *) arg = true;
  return DWARF_CB_OK;
}

struct process_dwflmod_args
{
  int fd;
  bool only_one;
  PyObject *data;
};


/* Print file type.  */
static char *
print_file_type (unsigned short int e_type)
{
  char *magic;
  magic = malloc(80 * sizeof(char));

  memset (magic , '\0', 80);

  if (likely (e_type <= ET_CORE))
    {
      static const char *const knowntypes[] =
      {
        "NONE (None)",
        "REL (Relocatable file)",
        "EXEC (Executable file)",
        "DYN (Shared object file)",
        "CORE (Core file)"
      };
      sprintf(magic, "%s", knowntypes[e_type]);
    }
  else if (e_type >= ET_LOOS && e_type <= ET_HIOS)
    sprintf (magic, "OS Specific: (%x)\n",  e_type);
  else if (e_type >= ET_LOPROC /* && e_type <= ET_HIPROC always true */)
    sprintf (magic, "Processor Specific: (%x)\n",  e_type);
  else
    sprintf(magic, "???");

  return magic;
}






PyObject *
process_elf_file (Dwfl_Module *dwflmod, int fd)
{
  PyObject *result = PyDict_New();
  GElf_Addr dwflbias;
  Elf *elf = dwfl_module_getelf (dwflmod, &dwflbias);

  GElf_Ehdr ehdr_mem;
  GElf_Ehdr *ehdr = gelf_getehdr (elf, &ehdr_mem);

  if (ehdr == NULL)
    {
    elf_error:
      error (0, 0, "cannot read ELF header: %s", elf_errmsg (-1));
      Py_INCREF(Py_None);
      return Py_None;
    }

  Ebl *ebl = ebl_openbackend (elf);
  if (unlikely (ebl == NULL))
    {
    ebl_error:
      error (0, errno, "cannot create EBL handle");
      Py_INCREF(Py_None);
      return Py_None;
    }

  /* Determine the number of sections.  */
  if (unlikely (elf_getshdrnum (ebl->elf, &shnum) < 0))
    error (EXIT_FAILURE, 0,
           gettext ("cannot determine number of sections: %s"),
           elf_errmsg (-1));

  /* Determine the number of phdrs. */
  if (unlikely (elf_getphdrnum (ebl->elf, &phnum) < 0))
    error (EXIT_FAILURE, 0,
           "cannot determine number of program headers: %s",
           elf_errmsg (-1));

  /* For an ET_REL file, libdwfl has adjusted the in-core shdrs
     and may have applied relocation to some sections.
     So we need to get a fresh Elf handle on the file to display those.  */
  bool print_unrelocated = true;

  Elf *pure_elf = NULL;
  Ebl *pure_ebl = ebl;
  if (ehdr->e_type == ET_REL && print_unrelocated)
    {
      /* Read the file afresh.  */
      off64_t aroff = elf_getaroff (elf);
      pure_elf = elf_begin (fd, ELF_C_READ_MMAP, NULL);
      if (aroff > 0)
        {
          /* Archive member.  */
          (void) elf_rand (pure_elf, aroff);
          Elf *armem = elf_begin (-1, ELF_C_READ_MMAP, pure_elf);
          elf_end (pure_elf);
          pure_elf = armem;
        }
      if (pure_elf == NULL)
        goto elf_error;
      pure_ebl = ebl_openbackend (pure_elf);
      if (pure_ebl == NULL)
        goto ebl_error;
    }

  PyObject *pyheader = print_ehdr (ebl, ehdr);
  PyDict_SetItem(result, PyString_FromString("header"), pyheader);

  PyObject *pysymtab = print_symtab (ebl, SHT_DYNSYM);
  PyDict_SetItem(result, PyString_FromString("dynsym"), pysymtab);
  if (pysymtab == NULL)
      printf("Getting NULL systab");
  ebl_closebackend (ebl);

  if (pure_ebl != ebl)
    {
      ebl_closebackend (pure_ebl);
      elf_end (pure_elf);
    }

  return result;

}

/* Print ELF header.  */
PyObject *
print_ehdr (Ebl *ebl, GElf_Ehdr *ehdr)
{
  size_t cnt = 0;
  char magic[80];
  memset (magic , '\0', 80);
  PyObject *pymagic = NULL;
  PyObject *pyclass = NULL;
  PyObject *pydata = NULL;
  PyObject *pyident = NULL;
  PyObject *pyosabi = NULL;
  PyObject *pyabiversion = NULL;
  PyObject *pytype = NULL;
  PyObject *pymachine = NULL;
  PyObject *pyelfversion = NULL;
  PyObject *pyentryaddress = NULL;
  PyObject *pystartprogramhdr = NULL;
  PyObject *pystartsectionhdr = NULL;
  PyObject *pyflag = NULL;
  PyObject *pysizeofhdr = NULL;
  PyObject *pystrhdr = NULL;
  PyObject *resultdict = PyDict_New();

  /*fputs_unlocked (gettext ("ELF Header:\n  Magic:  "), stdout);*/
  for ( ;cnt < EI_NIDENT; ++cnt)
  {
    char buf[4];
    memset(buf, '\0', 4);
    sprintf(buf, " %02hhx", ehdr->e_ident[cnt]);
    strcat(magic, buf);
  }

  pymagic = PyString_FromString(magic);

  pyclass = PyString_FromString(ehdr->e_ident[EI_CLASS] == ELFCLASS32 ? "ELF32"
          : ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64"
          : "\?\?\?");

  pydata = PyString_FromString(ehdr->e_ident[EI_DATA] == ELFDATA2LSB
          ? "2's complement, little endian"
          : ehdr->e_ident[EI_DATA] == ELFDATA2MSB
          ? "2's complement, big endian" : "\?\?\?");

  memset (magic , '\0', 80);
  sprintf (magic, "%hhd %s",
          ehdr->e_ident[EI_VERSION],
          ehdr->e_ident[EI_VERSION] == EV_CURRENT ? gettext ("(current)")
          : "(\?\?\?)");
  pyident = PyString_FromString(magic);

  char buf[512];
  pyosabi = PyString_FromString(ebl_osabi_name (ebl, ehdr->e_ident[EI_OSABI], buf, sizeof (buf)));

  memset (magic , '\0', 80);
  sprintf (magic,"%hhd", ehdr->e_ident[EI_ABIVERSION]);
  pyabiversion = PyString_FromString (magic);


  char *tmpdata = print_file_type (ehdr->e_type);
  pytype = PyString_FromString(tmpdata);
  free(tmpdata);

  pymachine = PyString_FromString(ebl->name);

  memset (magic , '\0', 80);
  sprintf (magic, "%d %s", ehdr->e_version,
          ehdr->e_version  == EV_CURRENT ? gettext ("(current)") : "(\?\?\?)");
  pyelfversion = PyString_FromString(magic);

  /* Entry Point Address */
  memset (magic , '\0', 80);
  sprintf (magic, "%#" PRIx64, ehdr->e_entry);
  pyentryaddress = PyString_FromString(magic);

  /* Start of Program address */
  memset (magic , '\0', 80);
  sprintf (magic, "%" PRId64 " (bytes into file)", ehdr->e_phoff);
  pystartprogramhdr = PyString_FromString(magic);

  /* Start of Section address */
  memset (magic , '\0', 80);
  sprintf (magic, "%" PRId64 " (bytes into file)", ehdr->e_shoff);
  pystartsectionhdr = PyString_FromString(magic);

  pyflag = PyString_FromString(
          ebl_machine_flag_name (ebl, ehdr->e_flags, buf, sizeof (buf)));

  /* Size of this header */
  memset (magic , '\0', 80);
  sprintf(magic, "%" PRId16 " %s",
          ehdr->e_ehsize, gettext ("(bytes)"));
  pysizeofhdr = PyString_FromString(magic);

  /* Size of Program header entries */
  memset (magic , '\0', 80);
  sprintf (magic, "%" PRId16 " %s",
          ehdr->e_phentsize, gettext ("(bytes)"));
  PyObject *pyprghdr = PyString_FromString(magic);

  /* Number of program headers entries */
  memset (magic , '\0', 80);
  sprintf (magic, "%" PRId16 , ehdr->e_phnum);
  PyObject *pynprghdr = PyString_FromString(magic);

  /*if (ehdr->e_phnum == PN_XNUM)
    {
      GElf_Shdr shdr_mem;
      GElf_Shdr *shdr = gelf_getshdr (elf_getscn (ebl->elf, 0), &shdr_mem);
      if (shdr != NULL)
        printf (gettext (" (%" PRIu32 " in [0].sh_info)"),
                (uint32_t) shdr->sh_info);
      else
        fputs_unlocked (gettext (" ([0] not available)"), stdout);
    }
  fputc_unlocked ('\n', stdout); */

  /*Size of section headers */
  memset (magic , '\0', 80);
  sprintf (magic, "%" PRId16 " (bytes)", ehdr->e_shentsize);
  PyObject *pysechdr = PyString_FromString(magic);

  /* Number of section headers */
  memset (magic , '\0', 80);
  sprintf (magic, "%" PRId16, ehdr->e_shnum);
  PyObject *pynsechdr = PyString_FromString(magic);

  if (ehdr->e_shnum == 0)
    {
      GElf_Shdr shdr_mem;
      GElf_Shdr *shdr = gelf_getshdr (elf_getscn (ebl->elf, 0), &shdr_mem);
      if (shdr != NULL)
        printf (gettext (" (%" PRIu32 " in [0].sh_size)"),
                (uint32_t) shdr->sh_size);
      else
        fputs_unlocked (gettext (" ([0] not available)"), stdout);
    }
  fputc_unlocked ('\n', stdout);

  /* Section header string table index */
  memset (magic , '\0', 80);
  if (unlikely (ehdr->e_shstrndx == SHN_XINDEX))
    {
      GElf_Shdr shdr_mem;
      GElf_Shdr *shdr = gelf_getshdr (elf_getscn (ebl->elf, 0), &shdr_mem);
      if (shdr != NULL)
        /* We managed to get the zeroth section.  */
        snprintf (buf, sizeof (buf), gettext (" (%" PRIu32 " in [0].sh_link)"),
                  (uint32_t) shdr->sh_link);
      else
        {
          strncpy (buf, gettext (" ([0] not available)"), sizeof (buf));
          buf[sizeof (buf) - 1] = '\0';
        }

      sprintf (magic,"XINDEX%s", buf);
    }
  else
   sprintf (magic, "%" PRId16, ehdr->e_shstrndx);
  pystrhdr = PyString_FromString(magic);

  /* Fill the dictionary to return*/
  PyDict_SetItem(resultdict, PyString_FromString("magic"), pymagic);
  PyDict_SetItem(resultdict, PyString_FromString("class"), pyclass);
  PyDict_SetItem(resultdict, PyString_FromString("data"), pydata);
  PyDict_SetItem(resultdict, PyString_FromString("ident"), pyident);
  PyDict_SetItem(resultdict, PyString_FromString("os/abi"), pyosabi);
  PyDict_SetItem(resultdict, PyString_FromString("abiversion"), pyabiversion);
  PyDict_SetItem(resultdict, PyString_FromString("type"), pytype);
  PyDict_SetItem(resultdict, PyString_FromString("machine"), pymachine);
  PyDict_SetItem(resultdict, PyString_FromString("elfversion"), pyelfversion);
  PyDict_SetItem(resultdict, PyString_FromString("entrypointaddress"), pyentryaddress);
  PyDict_SetItem(resultdict, PyString_FromString("startofprogramheader"), pystartprogramhdr);
  PyDict_SetItem(resultdict, PyString_FromString("startofsectionheader"), pystartsectionhdr);
  PyDict_SetItem(resultdict, PyString_FromString("flags"), pyflag);
  PyDict_SetItem(resultdict, PyString_FromString("sizeofthisheader"), pysizeofhdr);
  PyDict_SetItem(resultdict, PyString_FromString("sizeofprogramheader"), pyprghdr);
  PyDict_SetItem(resultdict, PyString_FromString("numberofprogramheader"), pynprghdr);
  PyDict_SetItem(resultdict, PyString_FromString("sizeofsectionheader"), pysechdr);
  PyDict_SetItem(resultdict, PyString_FromString("numberofsectionheader"), pynsechdr);
  PyDict_SetItem(resultdict, PyString_FromString("stringheaderindex"), pystrhdr);

  return resultdict;
}

static const char *
get_visibility_type (int value)
{
  switch (value)
    {    
    case STV_DEFAULT:
      return "DEFAULT";
    case STV_INTERNAL:
      return "INTERNAL";
    case STV_HIDDEN:
      return "HIDDEN";
    case STV_PROTECTED:
      return "PROTECTED";
    default:
      return "???";
    }    
}

/* Print the program header.  */
PyObject *
print_symtab (Ebl *ebl, int type)
{
  /* Find the symbol table(s).  For this we have to search through the
     section table.  */
  Elf_Scn *scn = NULL;

  while ((scn = elf_nextscn (ebl->elf, scn)) != NULL)
    {
      /* Handle the section if it is a symbol table.  */
      GElf_Shdr shdr_mem;
      GElf_Shdr *shdr = gelf_getshdr (scn, &shdr_mem);

      if (shdr != NULL && shdr->sh_type == (GElf_Word) type)
	return handle_symtab (ebl, scn, shdr);
    }
    printf("We are here\n");
    Py_INCREF(Py_None);
    return Py_None;
}


PyObject *
handle_symtab (Ebl *ebl, Elf_Scn *scn, GElf_Shdr *shdr)
{

  PyObject *result = PyList_New(0);
  Elf_Data *versym_data = NULL;
  Elf_Data *verneed_data = NULL;
  Elf_Data *verdef_data = NULL;
  Elf_Data *xndx_data = NULL;
  int class = gelf_getclass (ebl->elf);
  Elf32_Word verneed_stridx = 0;
  Elf32_Word verdef_stridx = 0;

  /* Get the data of the section.  */
  Elf_Data *data = elf_getdata (scn, NULL);
  if (data == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }

  /* Find out whether we have other sections we might need.  */
  Elf_Scn *runscn = NULL;
  while ((runscn = elf_nextscn (ebl->elf, runscn)) != NULL)
    {
      GElf_Shdr runshdr_mem;
      GElf_Shdr *runshdr = gelf_getshdr (runscn, &runshdr_mem);

      if (likely (runshdr != NULL))
	{
	  if (runshdr->sh_type == SHT_GNU_versym
	      && runshdr->sh_link == elf_ndxscn (scn))
	    /* Bingo, found the version information.  Now get the data.  */
	    versym_data = elf_getdata (runscn, NULL);
	  else if (runshdr->sh_type == SHT_GNU_verneed)
	    {
	      /* This is the information about the needed versions.  */
	      verneed_data = elf_getdata (runscn, NULL);
	      verneed_stridx = runshdr->sh_link;
	    }
	  else if (runshdr->sh_type == SHT_GNU_verdef)
	    {
	      /* This is the information about the defined versions.  */
	      verdef_data = elf_getdata (runscn, NULL);
	      verdef_stridx = runshdr->sh_link;
	    }
	  else if (runshdr->sh_type == SHT_SYMTAB_SHNDX
	      && runshdr->sh_link == elf_ndxscn (scn))
	    /* Extended section index.  */
	    xndx_data = elf_getdata (runscn, NULL);
	}
    }

  /* Get the section header string table index.  */
  size_t shstrndx;
  if (unlikely (elf_getshdrstrndx (ebl->elf, &shstrndx) < 0))
    error (EXIT_FAILURE, 0,
	   gettext ("cannot get section header string table index"));

  /* Now we can compute the number of entries in the section.  */
  unsigned int nsyms = data->d_size / (class == ELFCLASS32
				       ? sizeof (Elf32_Sym)
				       : sizeof (Elf64_Sym));

  /*
  printf (ngettext ("\nSymbol table [%2u] '%s' contains %u entry:\n",
		    "\nSymbol table [%2u] '%s' contains %u entries:\n",
		    nsyms),
	  (unsigned int) elf_ndxscn (scn),
	  elf_strptr (ebl->elf, shstrndx, shdr->sh_name), nsyms);
  GElf_Shdr glink;
  printf (ngettext (" %lu local symbol  String table: [%2u] '%s'\n",
		    " %lu local symbols  String table: [%2u] '%s'\n",
		    shdr->sh_info),
	  (unsigned long int) shdr->sh_info,
	  (unsigned int) shdr->sh_link,
	  elf_strptr (ebl->elf, shstrndx,
		      gelf_getshdr (elf_getscn (ebl->elf, shdr->sh_link),
				    &glink)->sh_name));

  fputs_unlocked (class == ELFCLASS32
		  ? gettext ("\
  Num:    Value   Size Type    Bind   Vis          Ndx Name\n")
		  : gettext ("\
  Num:            Value   Size Type    Bind   Vis          Ndx Name\n"),
		  stdout);*/

  for (unsigned int cnt = 0; cnt < nsyms; ++cnt)
    {
      PyObject *resultdict = PyDict_New();
      char magic[280];
      memset (magic , '\0', 280);
      char typebuf[64];
      char bindbuf[64];
      char scnbuf[64];
      Elf32_Word xndx;
      GElf_Sym sym_mem;
      GElf_Sym *sym = gelf_getsymshndx (data, xndx_data, cnt, &sym_mem, &xndx);

      if (unlikely (sym == NULL))
	continue;

      /* Determine the real section index.  */
      if (likely (sym->st_shndx != SHN_XINDEX))
	xndx = sym->st_shndx;
      /*
      printf (gettext ("\
%5u: %0*" PRIx64 " %6" PRId64 " %-7s %-6s %-9s %6s %s"),
	      cnt,
	      class == ELFCLASS32 ? 8 : 16,
	      sym->st_value,
	      sym->st_size,
	      ebl_symbol_type_name (ebl, GELF_ST_TYPE (sym->st_info),
				    typebuf, sizeof (typebuf)),
	      ebl_symbol_binding_name (ebl, GELF_ST_BIND (sym->st_info),
				       bindbuf, sizeof (bindbuf)),
	      get_visibility_type (GELF_ST_VISIBILITY (sym->st_other)),
	      ebl_section_name (ebl, sym->st_shndx, xndx, scnbuf,
				sizeof (scnbuf), NULL, shnum),
	      elf_strptr (ebl->elf, shdr->sh_link, sym->st_name));
      */
      /*
      sprintf ("%0*" PRIx64, sym->st_value);
      PyObject *pyvalue = PyString_FromString(magic);
      PyDict_SetItem(resultdict, PyString_FromString("value"), pyvalue);


      memset (magic , '\0', 280);
      sprintf ("%6" PRId64, sym->st_size);
      PyObject *pysize = PyString_FromString(sym->magic);
      PyDict_SetItem(resultdict, PyString_FromString("size"), pysize);
      memset (magic , '\0', 280);
      */
      PyObject *pytype = PyString_FromString(ebl_symbol_type_name (ebl, GELF_ST_TYPE (sym->st_info),
				    typebuf, sizeof (typebuf)));
      PyDict_SetItem(resultdict, PyString_FromString("type"), pytype);

      PyObject *pybind = PyString_FromString(ebl_symbol_binding_name (ebl, GELF_ST_BIND (sym->st_info),
				       bindbuf, sizeof (bindbuf)));
      PyDict_SetItem(resultdict, PyString_FromString("bind"), pybind);

      PyObject *pyvis = PyString_FromString(get_visibility_type (GELF_ST_VISIBILITY (sym->st_other)));
      PyDict_SetItem(resultdict, PyString_FromString("vis"), pyvis);

      sprintf(magic,"%s",ebl_section_name (ebl, sym->st_shndx, xndx, scnbuf,
				sizeof (scnbuf), NULL, shnum));
      PyObject *pyndx = PyString_FromString(gettext(magic));
      memset (magic , '\0', 280);

      PyDict_SetItem(resultdict, PyString_FromString("ndx"), pyndx);

      PyObject *pyname = PyString_FromString(elf_strptr (ebl->elf, shdr->sh_link, sym->st_name));
      PyDict_SetItem(resultdict, PyString_FromString("name"), pyname);


      if (versym_data != NULL)
	{
	  /* Get the version information.  */
	  GElf_Versym versym_mem;
	  GElf_Versym *versym = gelf_getversym (versym_data, cnt, &versym_mem);

	  if (versym != NULL && ((*versym & 0x8000) != 0 || *versym > 1))
	    {
	      bool is_nobits = false;
	      bool check_def = xndx != SHN_UNDEF;

	      if (xndx < SHN_LORESERVE || sym->st_shndx == SHN_XINDEX)
		{
		  GElf_Shdr symshdr_mem;
		  GElf_Shdr *symshdr =
		    gelf_getshdr (elf_getscn (ebl->elf, xndx), &symshdr_mem);

		  is_nobits = (symshdr != NULL
			       && symshdr->sh_type == SHT_NOBITS);
		}

	      if (is_nobits || ! check_def)
		{
		  /* We must test both.  */
		  GElf_Vernaux vernaux_mem;
		  GElf_Vernaux *vernaux = NULL;
		  size_t vn_offset = 0;

		  GElf_Verneed verneed_mem;
		  GElf_Verneed *verneed = gelf_getverneed (verneed_data, 0,
							   &verneed_mem);
		  while (verneed != NULL)
		    {
		      size_t vna_offset = vn_offset;

		      vernaux = gelf_getvernaux (verneed_data,
						 vna_offset += verneed->vn_aux,
						 &vernaux_mem);
		      while (vernaux != NULL
			     && vernaux->vna_other != *versym
			     && vernaux->vna_next != 0)
			{
			  /* Update the offset.  */
			  vna_offset += vernaux->vna_next;

			  vernaux = (vernaux->vna_next == 0
				     ? NULL
				     : gelf_getvernaux (verneed_data,
							vna_offset,
							&vernaux_mem));
			}

		      /* Check whether we found the version.  */
		      if (vernaux != NULL && vernaux->vna_other == *versym)
			/* Found it.  */
			break;

		      vn_offset += verneed->vn_next;
		      verneed = (verneed->vn_next == 0
				 ? NULL
				 : gelf_getverneed (verneed_data, vn_offset,
						    &verneed_mem));
		    }

		  if (vernaux != NULL && vernaux->vna_other == *versym)
		    {
		      sprintf (magic, "@%s (%u)",
			      elf_strptr (ebl->elf, verneed_stridx,
					  vernaux->vna_name),
			      (unsigned int) vernaux->vna_other);
		      check_def = 0;
		    }
		  else if (unlikely (! is_nobits))
		    error (0, 0, gettext ("bad dynamic symbol"));
		  else
		    check_def = 1;
		}

	      if (check_def && *versym != 0x8001)
		{
		  /* We must test both.  */
		  size_t vd_offset = 0;

		  GElf_Verdef verdef_mem;
		  GElf_Verdef *verdef = gelf_getverdef (verdef_data, 0,
							&verdef_mem);
		  while (verdef != NULL)
		    {
		      if (verdef->vd_ndx == (*versym & 0x7fff))
			/* Found the definition.  */
			break;

		      vd_offset += verdef->vd_next;
		      verdef = (verdef->vd_next == 0
				? NULL
				: gelf_getverdef (verdef_data, vd_offset,
						  &verdef_mem));
		    }

		  if (verdef != NULL)
		    {
		      GElf_Verdaux verdaux_mem;
		      GElf_Verdaux *verdaux
			= gelf_getverdaux (verdef_data,
					   vd_offset + verdef->vd_aux,
					   &verdaux_mem);

		      if (verdaux != NULL)
			sprintf (magic, (*versym & 0x8000) ? "@%s" : "@@%s",
				elf_strptr (ebl->elf, verdef_stridx,
					    verdaux->vda_name));
		    }
		}
	    }
        PyObject *pysymver = PyString_FromString(magic);
        PyDict_SetItem(resultdict, PyString_FromString("symbolversion"), pysymver);

        PyList_Append(result,resultdict);
	}

      /*putchar_unlocked ('\n');*/
    }
    return result;
}

static int
process_dwflmod (Dwfl_Module *dwflmod,
                 void **userdata __attribute__ ((unused)),
                 const char *name __attribute__ ((unused)),
                 Dwarf_Addr base __attribute__ ((unused)),
                 void *arg)
{
  struct process_dwflmod_args *a = arg;
  PyObject *data = NULL;

  /* Print the file name.  */
  if (!a->only_one)
    {
      const char *fname;
      dwfl_module_info (dwflmod, NULL, NULL, NULL, NULL, NULL, &fname, NULL);

      printf ("\n%s:\n\n", fname);
    }

  data = process_elf_file (dwflmod, a->fd);
  PyList_Append(a->data, data);

  return DWARF_CB_OK;
}

static PyObject *
process_file (int fd, const char *fname, bool only_one)
{
  /* Duplicate an fd for dwfl_report_offline to swallow.  */
  int dwfl_fd = dup (fd);
  if (dwfl_fd < 0)
    error (EXIT_FAILURE, errno, "dup2");


  /* Process the one or more modules gleaned from this file.  */
  struct process_dwflmod_args a;

  /* Use libdwfl in a trivial way to open the libdw handle for us.
     This takes care of applying relocations to DWARF data in ET_REL files.  */
  static const Dwfl_Callbacks callbacks =
    {
      .section_address = dwfl_offline_section_address,
      .find_debuginfo = find_no_debuginfo
    };
  Dwfl *dwfl = dwfl_begin (&callbacks);
  /*if (dwfl != NULL)*/
    /* Let 0 be the logical address of the file (or first in archive).  */
    /*dwfl->offline_next_address = 0;*/
  if (dwfl_report_offline (dwfl, fname, fname, dwfl_fd) == NULL)
    {
      struct stat64 st;
      if (fstat64 (dwfl_fd, &st) != 0)
        error (0, errno, "cannot stat input file");
      else if (!(st.st_size == 0))
        error (0, 0, "input file is empty");
      else
        error (0, 0, "failed reading '%s': %s",
               fname, dwfl_errmsg (-1));
      close (dwfl_fd);          /* Consumed on success, not on failure.  */
      dwfl_end (dwfl);
      Py_INCREF(Py_None);
      return Py_None;
    } else
    {
      dwfl_report_end (dwfl, NULL, NULL);

      if (only_one)
        {
          /* Clear ONLY_ONE if we have multiple modules, from an archive.  */
          bool seen = false;
          only_one = dwfl_getmodules (dwfl, &count_dwflmod, &seen, 0) == 0;
        }

      /* Process the one or more modules gleaned from this file.  */
      a.fd = fd;
      a.only_one = only_one ;
      a.data = PyList_New(0);

      dwfl_getmodules (dwfl, &process_dwflmod, &a, 0);
    }
  dwfl_end (dwfl);
  return a.data;
}


static PyObject*
elfutils_parseelf(PyObject *self, PyObject *args)
{
    (void) self;

    const char* filename = NULL;
    PyObject *data = NULL;

    if (!PyArg_ParseTuple(args, "s", &filename))
                return NULL;

    elf_version (EV_CURRENT);
    int fd = open (filename, O_RDONLY);
    if (fd == -1)
    {
        error (0, errno, "cannot open input file");
        return NULL;
    }

    data = process_file (fd, filename, true);

    close (fd);
    return data;
}

static PyMethodDef ElfUtilsMethods[] = {
    {"parseelf",  elfutils_parseelf, METH_VARARGS,
     "Does some magic"},
    /*{"pythoncall",  kabireport_pythoncall, METH_VARARGS,
     "pass the python functions here"},*/
    {NULL, NULL, 0, NULL}        /* Sentinel */
};


PyMODINIT_FUNC
initelfutils(void)
{
        (void) Py_InitModule("elfutils", ElfUtilsMethods);
}


