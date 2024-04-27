#include<iostream>
#include<memory>
#include<vector>
#include<string>
#include<string_view>
#include<sha3.h>
#include<hex.h>
#include<utility>



template<typename span>
class Key{
	public:
		enum ExtensionCompare : uint8_t {kEqual = 0, kDiverge = 1, kKeyIsSubStr = 2, kNodeExtIsSubStr = 3};
		using CompareResult = std::pair<ExtensionCompare,size_t>;
		Key(span key):key_(key){}
		std::optional<uint8_t> GetAndAdvance(){
			if(current_location_ >= key_.size()) return std::nullopt;
			return static_cast<uint8_t>(key_.at(current_location_++));
		}
		std::optional<uint8_t> Get() const {
			if(current_location_ >= key_.size()) return std::nullopt;
			return static_cast<uint8_t>(key_.at(current_location_));
		}
		span KeySoFar() const {
			return key_.substr(0,current_location_);
		}
		span GetRestOfKey() const {
			return key_.substr(current_location_,key_.size());
		}
		span GetKey() const {
			return key_;
		}
		bool IsEnd() const {
			return current_location_ >= key_.size();
		}
		void Reset(){
			current_location_ = 0;
		}
		CompareResult CompareExtensions(const span& other_extension){
			int equals = 0;
			const auto& key_extension = GetRestOfKey();
			std::cout << "Comparing [" << other_extension << "] to [" << key_extension << "]\n"; 
			if(other_extension == key_extension){
				return {kEqual,key_extension.size()};
			}
			if(other_extension.starts_with(key_extension)){
				return {kKeyIsSubStr,key_extension.size()};
			}
			if(key_extension.starts_with(other_extension)){
				return {kNodeExtIsSubStr,other_extension.size()};
			}
			auto min = std::min(key_extension.size(),other_extension.size());	
			size_t match = 0;
			for(match ; match < min; ++match ){
				if(key_extension[match] != other_extension[match]){
					break;
				}
			}
			return {kDiverge,match};
		}
		void AdvanceBy(size_t count){
			//assert
			current_location_ += count;
		}
		
	private:
		span key_;
		size_t current_location_ = 0;

};

std::string CALC_SHA3_256(const std::string& input) {
    using namespace CryptoPP;

    SHA3_256 hash;
    std::string digest;

    // Calculate the SHA3-256 hash
    StringSource s(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    return digest;
}



class INode {
	public:
		enum Type : uint8_t {kBranch = 0, kHashOfBranch = 1, kHashOfRecord = 2 , kNull = 3};
		virtual ~INode(){}
		virtual Type GetType() const = 0;
		//replace std::string with hash type
		virtual const std::string& Hash() const = 0;
		virtual void SetExtension(std::string extension) = 0;
		virtual const std::string& Extension() const = 0;
		virtual void Print() const = 0;
};

// should be a single global instance of this
class NullNode : public INode {
	public:
		static std::string kHash;
		static std::string kEmptyExtension;
		Type GetType() const override { return Type::kNull;}
		const std::string& Hash() const override { return kHash;}
		void SetExtension(std::string extension) override {}
		const std::string& Extension() const override { return kEmptyExtension;}
		void Print() const override {};
}; 
std::string NullNode::kHash = "";
std::string NullNode::kEmptyExtension = "";

class BranchNode : public INode {
	public:
		static size_t kBranchingFactor;
		BranchNode():children_(kBranchingFactor){
		//assert branching > 0	
		}
		Type GetType() const override { return Type::kBranch;}
		const std::string& Hash() const override { return hash_;}
		void SetExtension(std::string extension) override {
			extension_ = std::move(extension);
		}
		const std::string& Extension() const override { return extension_;}
		
		//Specific to branchNode
		std::unique_ptr<INode>& GetChildAt(uint8_t idx) {
			//assert
			return children_.at(idx);
		}
		std::unique_ptr<INode>& GetTerminationLeaf() {
			return children_.at(children_.size()-1);
		}

		void Print() const override{
			std::cout << "Branch node with extension " << extension_ << " hash " << hash_ << " children:\n";
			for(int i = 0 ; i < children_.size() ; ++i){
				std::cout << i << ":";
				if(!children_.at(i)){
					std::cout << "NullNode|";
					continue;
				}
				children_.at(i)->Print();
			}

		}

	private:
		std::vector<std::unique_ptr<INode>> children_;
		std::string extension_;
		std::string hash_;
};

size_t BranchNode::kBranchingFactor = 0;

class HashOfBranchNode : public INode {
	public:
		explicit HashOfBranchNode(bool is_dirty):is_dirty_(is_dirty){}
		Type GetType() const override { return Type::kHashOfBranch;}
        const std::string& Hash() const override { return hash_;} 
		void SetExtension(std::string extension) override {extension_ = std::move(extension);} 
        const std::string& Extension() const override { return extension_;}

		//Specific to hash of branch 
		bool IsDirty() const {return is_dirty_;}
		void SetDirty(bool is_dirty){
			is_dirty_ = is_dirty;
		}
		void Print() const override{
			std::cout << "HashOfBranchNode: extension " << extension_ << " is dirty " << is_dirty_ << " hash " << hash_ << "\n";
		}
	private:
		std::string extension_;
        std::string hash_;
		bool is_dirty_ = false;
};
template<typename span>
class HashOfRecord : public INode {
    public:
        Type GetType() const override { return Type::kHashOfRecord;}
		HashOfRecord(const span& key, const std::string& value){
			//optimize
			std::string to_digest = std::to_string(key.size()) + std::string(key) + value;
			hash_ = CALC_SHA3_256(to_digest);
			std::cout << "Digest of " << to_digest << " is " << hash_ << "\n";
		}
        const std::string& Hash() const override { return hash_;}       
		void SetExtension(std::string extension) override {extension_ = std::move(extension);}
        const std::string& Extension() const override { return extension_;}
		void Print() const override{
			std::cout << "HashOfRecord: extension " << extension_ << " hash " << hash_ << "\n";
		}

    private:
    	 std::string extension_;
        std::string hash_;
};

class InMemTree{
public:
	static std::string kRootKey;
	InMemTree(){
		db_[kRootKey] = std::unique_ptr<BranchNode>(new BranchNode{});
	}
	template<typename span>
	void Insert(Key<span>& key,const std::string& value){
		Insert(key,value,db_[kRootKey]);
	}
	template<typename span>
	void Insert(Key<span>& key,const std::string& value,std::unique_ptr<BranchNode>& branch_node){
		std::cout << "---------------------------------------------------------------------------\n";
		std::cout << "Inserting key [" << key.GetKey() << "] path so far [" << key.KeySoFar() << "] remaining path [" << key.GetRestOfKey() << "] current branchNode extension [" << branch_node->Extension() << "]\n";
		auto current_node_extension_compare = key.CompareExtensions(branch_node->Extension());
		if(current_node_extension_compare.first == Key<span>::kEqual){
			std::cout << "Extensions of branch node and key matches, adding it at last child\n";
			auto& leaf = branch_node->GetTerminationLeaf();
			leaf.reset(new HashOfRecord(key.GetKey(),value));
			return;
		}
		if(current_node_extension_compare.first == Key<span>::kKeyIsSubStr){
			std::cout << "Key is substr of branch node, need to diverge, key extension [" << key.GetRestOfKey() << "] node extension [" << branch_node->Extension() << "]\n" ;
			//create new branch node with inserted key as last child and hashOfbranch for the current node
			std::cout << "Replacing branch node at key " << key.KeySoFar() << " with new branch node with extension " << key.GetRestOfKey() << "\n";
			auto swap_branch_node = std::unique_ptr<BranchNode>(new BranchNode{});
			swap_branch_node->SetExtension(std::string(key.GetRestOfKey()));
			auto& leaf = swap_branch_node->GetTerminationLeaf();
			leaf.reset(new HashOfRecord(key.GetKey(),value));
			const auto& current_extension = branch_node->Extension();
			auto next_symbol = current_extension[current_node_extension_compare.second];
			auto hash_of_branch = std::unique_ptr<INode>(new HashOfBranchNode(true));
			auto truncated_extension = current_extension.substr(current_node_extension_compare.second+1,current_extension.size());
			hash_of_branch->SetExtension(truncated_extension);
			swap_branch_node->GetChildAt(next_symbol).swap(hash_of_branch);
			std::cout << "New branch node with new record at leaf and hash of branch to current node at " << next_symbol << "\n";
			swap_branch_node->Print();
			swap_branch_node.swap(branch_node);
			// now swap_branch_node contains the branch node that needs to be truncated and stored in db_
			swap_branch_node->SetExtension(truncated_extension);
			auto new_key = std::string{key.GetKey()} + next_symbol;
			std::cout << "Modifying current branch extension to " << truncated_extension << " and adding it to db at key " << new_key << "\n";
			swap_branch_node->Print();
			db_[new_key].swap(swap_branch_node);
			return;
		}
		//Advance common extension
		key.AdvanceBy(current_node_extension_compare.second);
		// handle cases where key is at end?
		auto& child = branch_node->GetChildAt(*key.GetAndAdvance());
		//Null node
		if(!child){
			std::cout << "Current branch node does not have child at letter " << *key.Get() << " adding hash of Record\n";
			child.reset(new HashOfRecord(key.GetKey(),value));
			child->SetExtension(std::string(key.GetRestOfKey()));
			std::cout << "Added hashof record with extension " << child->Extension() << "\n";
			return;
		}
		if(child->GetType() == INode::kHashOfBranch){
				//mark dirty 
				static_cast<HashOfBranchNode*>(child.get())->SetDirty(true);
				//load corresponding branch node from db
				std::cout << "Encountered hash of branch, marking dirty and getting corresponding branch node with key " << key.KeySoFar() << "\n";
				auto branch_node_itr = db_.find(key.KeySoFar());
				//call insert
				std::cout << "Calling insert recursively with branch node \n";
				Insert(key,value,branch_node_itr->second);
				return;
		}
		//must be record node, it's either an update or new diverge
		auto extension_compare = key.CompareExtensions(child->Extension());
		if( extension_compare.first == Key<span>::kEqual){
			std::cout << "Extensions of node and rest of key, matches [" << child->Extension() << "]\n";
			std::cout << "This is an update to the record\n";
			child.reset(new HashOfRecord(key.GetKey(),value));
			child->SetExtension(std::string(key.GetRestOfKey()));
			return;
		}else{
			// I think this is the only place where new branch node are inserted since first we have a record and then diverge.
			std::cout << "need to diverge here by inserting new branch node to db and new hash of branch instead this, key extension " << key.GetRestOfKey() << " current child extension " << child->Extension() << "\n";
			std::cout << "Result of extension comparison is " << extension_compare.first << " num matches is " << extension_compare.second << "\n";
			auto new_node_extension = child->Extension().substr(0,extension_compare.second);
			auto to_swap_node = std::unique_ptr<INode>(new HashOfBranchNode(true));
			to_swap_node->SetExtension(std::string{new_node_extension});
			std::cout << "Adding new hash of branch\n";
			to_swap_node->Print();
			auto existing_record_extension = child->Extension();
			auto truncated_existing_record_extension = existing_record_extension.substr(extension_compare.second,existing_record_extension.size());
			//now to_swap holds the record node
			child.swap(to_swap_node);
			auto new_branch_node = std::unique_ptr<BranchNode>(new BranchNode{});
			new_branch_node->SetExtension(new_node_extension);
			//handle old record
			if(truncated_existing_record_extension.size() == 0 ){
				to_swap_node->SetExtension("");
				std::cout << "Existing record node extension is empty, adding to leaf\n";
				to_swap_node->Print();
				new_branch_node->GetTerminationLeaf().swap(to_swap_node);
			}else{
				auto symbol = truncated_existing_record_extension[0];
				to_swap_node->SetExtension(truncated_existing_record_extension.substr(1,truncated_existing_record_extension.size()));
				std::cout << "Existing record node extension is not empty, adding to child at " << symbol << "\n";
				to_swap_node->Print();
				new_branch_node->GetChildAt(symbol).swap(to_swap_node);
			}
			//handle new record
			auto new_record_extension = key.GetRestOfKey();
			auto truncated_new_record_extension = new_record_extension.substr(extension_compare.second,new_record_extension.size());
			auto new_record_node = std::unique_ptr<INode>(new HashOfRecord(key.GetKey(),value));
			if(truncated_new_record_extension.size() == 0 ){
				std::cout << "New record node extension is empty, adding to leaf\n";
				new_record_node->Print();
				new_branch_node->GetTerminationLeaf().swap(new_record_node);
			}else{
				auto symbol = truncated_new_record_extension[0];
				new_record_node->SetExtension(std::string{truncated_new_record_extension.substr(1,truncated_new_record_extension.size())});
				std::cout << "New record node extension is not empty, adding to child at symbol  " << symbol << "\n";
				new_record_node->Print();
				new_branch_node->GetChildAt(symbol).swap(new_record_node);
			}

			auto new_branch_node_key = std::string{key.KeySoFar()};
			std::cout << "Adding new branch node at key " << new_branch_node_key << "\n";
			new_branch_node->Print();
			//set records at the new branch node
			db_[new_branch_node_key].swap(new_branch_node);
			return;
		}
	}
private:
	std::map<std::string,std::unique_ptr<BranchNode>,std::less<>> db_;
};

std::string InMemTree::kRootKey = "__rtt";

int main(){
	std::string key = "eran";
	std::string value = "lerer";
	auto key_rep = Key<std::string_view>(key);
	auto digit = key_rep.GetAndAdvance();
	while(digit){
		std::cout << *digit << " rest of key " << key_rep.GetRestOfKey() << " key so far " << key_rep.KeySoFar() << "\n";
		digit = key_rep.GetAndAdvance();
	}
	key_rep.Reset();
	BranchNode::kBranchingFactor = 257;
	NullNode::kHash = CALC_SHA3_256("HASH");
	auto tree = InMemTree{};
	tree.Insert(key_rep,value);
	{
		key_rep.Reset();
		std::string updated_value = "lereron";
		tree.Insert(key_rep,updated_value);
	}

	{
		std::string key = "eranit";
		std::string value = "lerer";
		auto key_rep = Key<std::string_view>(key);
		tree.Insert(key_rep,value);
	}

	{
		std::string key = "er";
		std::string value = "lerer";
		auto key_rep = Key<std::string_view>(key);
		tree.Insert(key_rep,value);
	}

	{
		std::string key = "moshe";
		std::string value = "lerer";
		auto key_rep = Key<std::string_view>(key);
		tree.Insert(key_rep,value);
	}

	{
		std::string key = "mosho";
		std::string value = "lerer";
		auto key_rep = Key<std::string_view>(key);
		tree.Insert(key_rep,value);
	}
	return 0;
}
