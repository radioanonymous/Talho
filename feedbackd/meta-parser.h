#pragma once
#include <string>

bool meta_init();
void meta_cleanup();
std::string meta_parse(const char *fname, std::string *mime = NULL);

