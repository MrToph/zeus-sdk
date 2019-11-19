// vrunclean(uint32_t size, std::vector<char> uri, name current_provider)

auto _self = name(current_receiver());
crypentries_t entries(_self, _self.value);
auto cidx = entries.get_index<"byhash"_n>();
auto existing = cidx.find(hashDataCRYP(uri));
if(existing != cidx.end()) cidx.erase(existing);
