#include<iostream>
#include<vector>
#include<unordered_map>
using namespace std;

void remove_group_owner(string group_name);
void remove_group_member(string group_name, string user_id);

struct session
{
    string user_id;
    string ip_port;

    bool is_logged_in = false;

    // for join request
    vector<string> group_requested; // groups that are requested
    vector<string> group_accepted;  // groups that are accepted;
}; // struct to store active session

// unordered_map<string, session> active_sessions;

struct group
{
    string name;
    string owner;
    vector<string> members;
    vector<pair<string,                            // file name
                pair<string,                       // hash
                     pair<string,                  // number of chunks;
                          vector<pair<string,      // client path
                                      string>>>>>> // client name
        shared_files;                             
    // vector<string,string> requests; //request to joint the group only ownwer can see contain group name and user name who requested.
    void enter_member(string member_name)
    {
        if (name == "/0")
            owner = member_name;
        else
            members.push_back(member_name);
    }
    void create_group(string creater_name)
    {
        name = creater_name;
        owner = creater_name;
        members.push_back(creater_name);
    }

    void add_member(string member_name)
    {
        members.push_back(member_name);
    }
    bool is_file_shared(string file_name)
    {
        for (auto i : shared_files)
        {
            if (i.first == file_name)
                return true;
        }
        return false;
    }
};

struct user
{
    string user_id;
    string password;
    session session_obj;
    // string latest_ip_port; // only available when online

    vector<string> groups_joined;
    // vector<group> groups_request_accepted;
    vector<string> groups_created;
    vector<string> file_sharing;
    vector<string> downloads;

    bool is_connected_to_group(string group_name)
    {
        for (auto i : groups_created)
        {
            if (i == group_name)
                return true;
        }
        for (auto i : groups_joined)
        {
            if (i == group_name)
                return true;
        }
        return false;
    }

    void created_group(string group_name)
    {
        groups_created.push_back(group_name);
    }

    /**
     * @brief exit_from_group removes user from given group and removes the group
     * from the user's joined groups list. If the user is the owner of the group,
     * it also removes the group from the user's created groups list and removes
     * the group from the tracker.
     *
     * @param group_name the name of the group to exit from
     */

    void exit_from_group(string group_name)
    {
        for (int i = 0; i < groups_created.size(); i++)
        {
            // if owner
            if (groups_created[i] == group_name)
            {
                groups_created.erase(groups_created.begin() + i);

                // groups[group_name].remove_owner();
                for (int i = 0; i < groups_joined.size(); i++)
                {
                    if (groups_joined[i] == group_name)
                    {
                        groups_joined.erase(groups_joined.begin() + i);
                        // groups[group_name].remove_member(user_id);
                    }
                }
                remove_group_owner(group_name); // sending user name
                return;
            }
        }
        // if not owner
        for (int i = 0; i < groups_joined.size(); i++)
        {
            if (groups_joined[i] == group_name)
            {
                groups_joined.erase(groups_joined.begin() + i);
                // groups[group_name].remove_member(user_id);
                remove_group_member(group_name, user_id);
                return;
            }
        }
    }
};
unordered_map<string, user> user_cred;          // map to store user credentials
unordered_map<string, group> groups;            // just to check if group exists
unordered_map<string, vector<string>> requests_group; // requests group group_name, user_name
unordered_map<string, vector<string>> requests_client; // requests name of user, group name

void remove_group_owner(string group_name)
{
    group &group_obj = groups[group_name];
    string owner_name = group_obj.owner;

    if (group_obj.members.size() <= 1)
    {
        groups.erase(group_name);
    }
    else
    {
        // if(group_obj.members.size()==2){
        //     for (int i = 0;i<)
        // }

        for (int i = 0; i < group_obj.members.size(); i++)
        {
            if (group_obj.members[i] == owner_name)
            {
                group_obj.members.erase(group_obj.members.begin() + i);
                continue;
            }
        }
        group_obj.owner = group_obj.members.front();
    }
}

void remove_group_member(string group_name, string user_id)
{
    group group_obj = groups[group_name];
    for (int i = 0; i < group_obj.members.size(); i++)
    {
        if (group_obj.members[i] == user_id)
        {
            group_obj.members.erase(group_obj.members.begin() + i);
        }
    }
}