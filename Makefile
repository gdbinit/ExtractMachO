PROC=extractmacho
O1=validate
O2=extractors

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)extractmacho$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
	          $(I)ua.hpp $(I)xref.hpp extractmacho.cpp

$(F)validate$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
	          $(I)ua.hpp $(I)xref.hpp validate.cpp

$(F)extractors$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
	          $(I)ua.hpp $(I)xref.hpp extractors.cpp
