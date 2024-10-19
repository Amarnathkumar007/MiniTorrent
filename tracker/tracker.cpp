/**
 * @file test_tracker2.cpp
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2024-10-12
 *
 * @copyright Copyright (c) 2024
 *
 */

/**
 * @brief when downlaod command client not getting the ip and port
 *
 *
 */

// Server side C program to demonstrate Socket
// programming
#include <netinet/in.h> //contians constant and structure needed for communtation
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <iostream>
#include <bits/stdc++.h>

#include "database.cpp"

#define PORT1 8080
#define PORT2 9090
#define PORT3 1010
#define PORT4 2020

#define number_of_trackers 4

using namespace std;

extern unordered_map<string, user> user_cred;                 // map to store user credentials
extern unordered_map<string, group> groups;                   // just to check if group exists
extern unordered_map<string, vector<string>> requests_group;  // requests group group_name, user_name
extern unordered_map<string, vector<string>> requests_client; // requests name of user, group name

string show_list(session &session_obj)
{
    user obj = user_cred[session_obj.user_id];
    string list_groups = "list of groups created: ";
    for (auto group_name : obj.groups_created)
    {
        list_groups = list_groups + group_name + " ";
    }

    list_groups += "\nlist of groups joined: ";
    for (auto group_name : obj.groups_joined)
    {
        list_groups = list_groups + group_name + " ";
    }
    return list_groups;
}

bool create_user(vector<string> command)
{
    string user_id = command[1];
    string password = command[2];
    if (user_cred.find(user_id) != user_cred.end())
    {
        // user exists
        cout << "\tuser already exist\n";
        return false;
    }
    else
    {
        // user not exist
        user user_obj;
        user_obj.user_id = user_id;
        user_obj.password = password;

        user_cred[user_id] = user_obj;

        cout << "user created successfully" << endl;
        return true;
    }
}

bool login(vector<string> command, session &session_obj)
{
    // login<user_id><passwd>
    string user_id = command[1];
    string password = command[2];
    if (user_cred.find(user_id) != user_cred.end())
    {
        if (user_cred[user_id].password == password)
        {
            cout << "user logged in successfully" << endl;
            session_obj.user_id = user_id;
            session_obj.is_logged_in = true;
            // update latest ip and port
            // active_sessions[session_obj.user_id] = session_obj;
            return true;
        }
        else
        {
            cout << "wrong password" << endl;
            return false;
        }
    }
    else
    {
        cout << "user does not exist" << endl;
        return false;
    }
}
void split(string command, vector<string> &command_vec)
{
    int pos = 0;
    string str;
    while (command.find(' ', pos) != string::npos)
    {
        str = command.substr(pos, command.find(' ', pos) - pos);
        command_vec.push_back(str);
        pos = command.find(' ', pos) + 1;
    }
    str = command.substr(pos);
    command_vec.push_back(str);
}

void send_message_to_client(string message, string print_statement, int new_socket)
{
    cout << print_statement << endl;
    send(new_socket, message.c_str(), message.size(), 0);
}

// int new_socket;
// void signalHandler(int signum)
// {
//     // cout << "Error in number of input provided\n";
//     send_message_to_client("Wrong #f of input\n", "Wrong #f of input\n", new_socket);
//     exit(signum);
// }

void thread_body_for_handling_client(int new_socket, int server_fd, sockaddr_in address, socklen_t addrlen, ssize_t valread)
{

    // signal(SIGSEGV, signalHandler); // to handle the out of bound exception

    // thread body
    session session_obj;
    char *hello = "hello from server";
    char buffer[1024];
    while (true)
    {
        valread = read(new_socket, buffer, 1024 - 1); // subtract 1 for the null
                                                      // terminator at the end
        printf("%s\n", buffer);
        send(new_socket, hello, strlen(hello), 0);
        printf("Hello message sent\n");

        if (valread == 0)
            return;
        while (true)
        {
            try
            {

                cout << "waiting for client command\n";
                memset(buffer, 0, sizeof(buffer));
                valread = read(new_socket, buffer, 1024 - 1);
                vector<string> command;
                split(buffer, command);
                if (command.empty())
                    continue;
                else if (command[0] == "create_user")
                {
                    cout << "tracker: creating user request\n";
                    if (create_user(command))
                    {
                        string message = "\tuser_id created successfully";
                        send(new_socket, message.c_str(), message.size(), 0);
                    }
                    else
                    {
                        string message = "\tuser_id already exist use different user_id";
                        send(new_socket, message.c_str(), message.size(), 0);
                    }
                }
                else if (command[0] == "login")
                {
                    cout << "tracker:  login request\n";
                    if (login(command, session_obj))
                    {
                        cout << "\tlogin successfull\n";
                        string message = "Y:login successful";

                        send(new_socket, message.c_str(), message.size(), 0);
                        cout << "waiting for ip and port\n";

                        valread = read(new_socket, buffer, 1024 - 1); // subtract 1 for the null
                        cout << "got ip and port now save into session\n";
                        string ip_port(buffer);

                        // done due to append of bad character at the last
                        if (ip_port[ip_port.size() - 1] >= '0' && ip_port[ip_port.size() - 1] <= '9')
                            session_obj.ip_port = ip_port; // save ip and port into session
                        else
                            session_obj.ip_port = ip_port.substr(0, ip_port.size() - 1);

                        cout << "ip and port " << session_obj.ip_port << endl;
                        user_cred[session_obj.user_id].session_obj = session_obj;

                        // user_cred[session_obj.user_id].latest_ip_port = session_obj.ip_port;
                    }
                    else
                    {
                        cout << "\tlogin unsuccessful\n";
                        string message = "N:login unsuccessful";
                        send(new_socket, message.c_str(), message.size(), 0);
                    };
                }
                else if (command[0] == "create_group")
                {
                    cout << "tracker:  creating group request\n";
                    if (session_obj.is_logged_in)
                    {
                        // is group name already exist
                        if (groups.find(command[1]) != groups.end())
                        {
                            string message = "group name already exist";
                            send(new_socket, message.c_str(), message.size(), 0);
                            continue;
                        }
                        // else create group
                        group group_obj;
                        group_obj.name = command[1];
                        group_obj.owner = session_obj.user_id;
                        group_obj.members.push_back(session_obj.user_id);
                        groups[group_obj.name] = group_obj;

                        user_cred[session_obj.user_id].groups_created.push_back(group_obj.name);
                        user_cred[session_obj.user_id].groups_joined.push_back(group_obj.name);

                        cout << "\tgroup created with name " << command[1] << "by user" << session_obj.user_id << endl;
                        string message = "group created successfully";
                        send(new_socket, message.c_str(), message.size(), 0);
                        continue;
                    }
                    cout << "\tclient not loggedin\n";
                    string message = "please logIn to create group";
                    send(new_socket, message.c_str(), message.size(), 0);
                }
                else if (command[0] == "join_group")
                {
                    // join_group group_id
                    cout << "tracker: group joining request\n";
                    if (session_obj.is_logged_in)
                    {
                        cout << "\n asked to join group: " << command[1] << endl; // group id

                        // is user already joined
                        int found = 0;
                        for (string s : user_cred[session_obj.user_id].groups_joined)
                        {
                            if (s == command[1])
                            {
                                cout << "Already in group\n";
                                send_message_to_client(" Already Connected to group\n", "client Aleady connected to group", new_socket);

                                found = 1;
                                continue;
                            }
                        }
                        if (found)
                            continue;

                        if (groups.find(command[1]) != groups.end())
                        {
                            // group exits
                            // groups[command[1]].requests.push_back(session_obj.user_id);

                            requests_group[command[1]].push_back(session_obj.user_id);  // stores group name and client id
                            requests_client[session_obj.user_id].push_back(command[1]); // store client id and group id
                            // groups[command[1]].add_member(session_obj.user_id);
                            // user_cred[session_obj.user_id].groups_joined.push_back(command[1]);

                            send_message_to_client(" Requested to join the group\n", "Successfully request to join group", new_socket);
                            continue;
                        }
                        // if(user_cred[session_obj.user_id].is_connected_to_group(session_obj.user_id)){
                        //     send_message_to_client("Already Connected to group\n","client couldn't create since already connected to group",new_socket);
                        //     continue;
                        // }
                        // if not joined then join
                        send_message_to_client("group name not exists\n", "group not exist", new_socket);
                        continue;
                    }
                    cout << "\tclient not loggedin\n";
                    string message = "please logIn to join group";
                    send(new_socket, message.c_str(), message.size(), 0);
                }
                else if (command[0] == "leave_group")
                {
                    cout << "tracker:  leave_group request\n";
                    // check if is in group()
                    if (session_obj.is_logged_in)
                    {
                        if (user_cred[session_obj.user_id].is_connected_to_group(command[1]))
                        {
                            user_cred[session_obj.user_id].exit_from_group(command[1]);
                            send_message_to_client("exited form group\n", "client exited from group", new_socket);
                        }
                        else
                        {
                            cout << "\tclient not connected to group\n";
                            string message = "not Connected to group\n";
                            send(new_socket, message.c_str(), message.size(), 0);
                        }
                    }
                    else
                    {
                        cout << "\tclient not loggedin\n";
                        string message = "please logIn to leave group";
                        send(new_socket, message.c_str(), message.size(), 0);
                    }
                }
                else if (command[0] == "list_requests")
                {
                    cout << "tracker:  list_requests request\n";
                    string requests = "";
                    // which ever group created search in request_groups

                    for (auto group_created : user_cred[session_obj.user_id].groups_created)
                    {
                        requests += "group name: ";
                        requests += group_created;
                        requests += " => ";

                        if (requests_group.find(group_created) != requests_group.end())
                        {
                            for (auto j : requests_group[group_created])
                            {
                                requests += j;
                                requests += " ";
                            }
                        }
                        requests += "\n";
                    }
                    string message = "Tracker: Here is the list of requests\n";
                    message += requests;

                    send_message_to_client(message, "sent list of group", new_socket);
                    continue;
                }
                else if (command[0] == "accept_request")
                {
                    // accept_request<group_id><user_id>
                    cout << "tracker:  accept_request request\n";
                    string group_id = command[1];
                    string user_id = command[2];
                    // check in request whether request exist
                    // if exist make changes in request_group and request_user
                    auto ptr = find(requests_group[group_id].begin(), requests_group[group_id].end(), user_id);
                    if (ptr != requests_group[group_id].end())
                    {
                        // user found and accept
                        requests_group[group_id].erase(ptr);

                        // now remove from request client array so that not appear in his request.
                        auto ptr = find(requests_client[user_id].begin(), requests_client[user_id].end(), user_id);
                        requests_client[user_id].erase(ptr);

                        // update in client
                        user_cred[user_id].groups_joined.push_back(group_id);
                        groups[group_id].add_member(user_id);

                        send_message_to_client("\tAccepted the group invitation", "Accepted the group invitation", new_socket);
                    }
                    else
                    {
                        // user not found send message to client
                        send_message_to_client("\tUser not found", "request for the user to join the user name not exist in the request box", new_socket);
                        continue;
                    }
                }
                else if (command[0] == "list_groups")
                {
                    cout << "tracker:  list_groups request\n";
                    if (session_obj.is_logged_in)
                    {
                        string group_created = show_list(session_obj);
                        cout << "list of groups: " << group_created; // print the list of groups
                        send(new_socket, group_created.c_str(), group_created.size(), 0);
                    }
                    else
                    {
                        string message = "Tracker: logIn to check group";
                        send(new_socket, message.c_str(), message.size(), 0);
                        cout << "\tuser not loggedIn to check List of group\n";
                    }
                }
                else if (command[0] == "upload_file")
                {

                    // upload_file <file_path> <group_id>
                    // incomming command "upload_file <file_name> <file_path> <group_id> <hash_string> <number of chunks>"
                    cout << "tracker:  upload_file request\n";
                    // check if file exits or not

                    // step 1: check if user logined in
                    if (!session_obj.is_logged_in)
                    {
                        // not logged in
                        send_message_to_client("please login and join the group to share files\n ", "User not loggedIn to share file\n", new_socket);
                        continue;
                    }
                    // step 2: check if user connected to group
                    cout << "checking is connected to group\n";
                    if (!user_cred[session_obj.user_id].is_connected_to_group(command[3]))
                    {
                        send_message_to_client("user not connected to group\n", "user not connected to group\n", new_socket);
                        continue;
                    }
                    // step3: check file if aleady exist if exist then check is it from same user if yes then delete old entry

                    // cout << "debug: 0";
                    // cout << "\nnumber of chunks" << command[5]; // number of chunks

                    group &group_obj = groups[command[3]];
                    // find the group_obj if file shared
                    int found = 0;
                    // auto itr = find(group_obj.shared_files.begin(), group_obj.shared_files.end(), command[1]);
                    // cout << "printing command varaible\n";
                    // for (auto i : command)
                    // {
                    //     cout << i << endl; // debug
                    // }

                    // upload_file
                    // data_set.txt
                    // /home/amarnath/Desktop/AOS/A3/clients/data_set.txt
                    // 510
                    // 629c30936852fa483fa474d0321510551003e763acf84cca66eb87cb001ab5884acf58275a7a0d5aed0a8d3a178855f83aeab30f3a4d83436c0406f38c49e9bba1e55907f8da3ec7769eafc086ba58f2209b7d5689b99eb7037ae670ad30222debb1089c79f181a006ca53b5b693763fe2e267857cf1eda20ba264b40e3366500b3a13b1f8b0f30a9bf10771
                    // 14

                    for (int i = 0; i < group_obj.shared_files.size(); i++)
                    {
                        if (command[1] == group_obj.shared_files[i].first) // same name
                        {
                            // check if from same user
                            for (int j = 0; j < group_obj.shared_files[i].second.second.second.size(); j++)
                            {
                                if (group_obj.shared_files[i].second.second.second[j].first == command[2]) // checking file path is same
                                {
                                    // means same user shared
                                    group_obj.shared_files[i].second.second.second.erase(group_obj.shared_files[i].second.second.second.begin() + j);
                                    break;
                                }
                            }

                            pair<string, pair<string, pair<string, vector<pair<string, string>>>>> &shared_files_temp_obj = group_obj.shared_files[i];

                            shared_files_temp_obj.first = command[1];               // file name
                            shared_files_temp_obj.second.first = command[4];        // hash
                            shared_files_temp_obj.second.second.first = command[5]; // number of chunks
                            // cout << "number of chunks " << shared_files_temp_obj.second.second.first<<"\n";
                            // cout << "here is hash" << command[6] << endl;
                            // cout << "input:";
                            // for (auto i : command)
                            // {
                            //     cout << i << "\t";
                            // }
                            // cout << endl;
                            shared_files_temp_obj.second.second.second.push_back({command[2], session_obj.user_id}); // path and client name
                            // group_obj.shared_files.push_back(shared_files_temp_obj);   // file name, hash, file path

                            // upload hash of file
                            send_message_to_client("\tFile Uploaded to group\n", "Hurrya!! File Uploaded to group\n", new_socket);
                            found = 1; // found
                            break;
                        }
                    }
                    if (found == 1)
                        continue;

                    // file not exist hence add into vector
                    pair<string, pair<string, pair<string, vector<pair<string, string>>>>> shared_files_temp_obj;
                    shared_files_temp_obj.first = command[1];                                                // file name
                    shared_files_temp_obj.second.first = command[4];                                         // hash
                    shared_files_temp_obj.second.second.first = command[5];                                  // number of chunks
                    shared_files_temp_obj.second.second.second.push_back({command[2], session_obj.user_id}); // path and clinet name

                    group_obj.shared_files.push_back(shared_files_temp_obj);
                    send_message_to_client("\tFile Uploaded to group\n", "Hurrya!! File Uploaded to group\n", new_socket);
                }
                else if (command[0] == "list_files")
                {
                    // list_files<group_id>
                    cout << "tracker:  list_files request\n";
                    // is user login
                    if (!session_obj.is_logged_in)
                    {
                        send_message_to_client("user not logedIn\n", "login and connect to group to check list of shared files\n", new_socket);
                        continue;
                    }
                    // is connected to group
                    if (!user_cred[session_obj.user_id].is_connected_to_group(command[1]))
                    {
                        send_message_to_client("user not connected to group\n", "user not connected to group\n", new_socket);
                        continue;
                    }
                    // now list all available file for download
                    group &group_obj = groups[command[1]]; // group object
                    string list_of_sharable_file = "list of sharable files in group:\n";
                    for (auto i : group_obj.shared_files)
                    {
                        list_of_sharable_file += i.first;
                        list_of_sharable_file += "\n";
                    }
                    send_message_to_client(list_of_sharable_file, "sending list of sharable files in the group\n", new_socket);
                }
                else if (command[0] == "download_file")
                {
                    // download_file<group_id><file_name><destination_path>
                    cout << "tracker:  download_file request\n";
                    // check if user logined in
                    if (!session_obj.is_logged_in)
                    {
                        send_message_to_client("user not logedIn\n", "login and connect to group to check list of shared files\n", new_socket);
                        continue;
                    }
                    // is connected to group
                    if (!user_cred[session_obj.user_id].is_connected_to_group(command[1]))
                    {
                        send_message_to_client("user not connected to group\n", "user not connected to group\n", new_socket);
                        continue;
                    }
                    // now check if file exist
                    group &group_obj = groups[command[1]];

                    if (!group_obj.is_file_shared(command[2]))
                    {
                        send_message_to_client("Given file name not shared in group\n", "Please enter correct file name given file name not shared\n", new_socket);
                        continue;
                    }
                    // send detail of file
                    user_cred[session_obj.user_id].downloads.push_back(command[2]);
                    string file_detail = "";
                    for (auto i : group_obj.shared_files)
                    {
                        if (i.first == command[2])
                        {

                            file_detail += i.first; // file name
                            file_detail += " ";
                            file_detail += i.second.first; // file hash
                            file_detail += " ";
                            file_detail += command[3]; // destination where client want to downlaod
                            file_detail += " ";
                            file_detail += i.second.second.first; // numbers of chunks
                            file_detail += " ";
                            file_detail += to_string(i.second.second.second.size()); // shared by number of clients
                            file_detail += " ";
                            for (auto j : i.second.second.second)
                            {
                                // file_detail += j.second; // user name
                                // file_detail += " ";
                                file_detail += user_cred[j.second].session_obj.ip_port; // user ip and port;
                                file_detail += " ";
                                file_detail += j.first; // user path
                                file_detail += " ";
                            }
                            break;
                        }
                    }
                    cout << file_detail << endl; // file detail
                    send_message_to_client(file_detail, "Sending detail of file\n", new_socket);
                    // formate: data_set.txt f2e22714b935659d26b36c559a863933548c2407  /home/amarnath/Desktop/AOS/A3/clients/data_set.txt /home/amarnath/Desktop/AOS/A3/client2/data_set.txt
                }
                else if (command[0] == "logout")
                {
                    cout << "tracker:  logout request\n";
                    // check if loggedIn
                    if (!session_obj.is_logged_in)
                    {
                        send_message_to_client("user not logedIn\n", "login first then logout\n", new_socket);
                        continue;
                    }
                    session_obj.is_logged_in = false;
                    send_message_to_client("successfully logout\n Session closed\n", "successfully logout", new_socket);
                    break;
                }
                else if (command[0] == "stop_sharing")
                {
                    // stop_share <group_id> <file_name>
                    // is the client logged in
                    if (!session_obj.is_logged_in)
                    {
                        string message = "Tracker: logIn and join the group to stop sharing\n";
                        send(new_socket, message.c_str(), message.size(), 0);
                        cout << "\tuser not loggedIn to check List of group\n";
                        continue;
                    }
                    // is the clinet connected to group
                    if (!user_cred[session_obj.user_id].is_connected_to_group(command[1]))
                    {
                        send_message_to_client("user not connected to group\n", "user not connected to group\n", new_socket);
                        continue;
                    }
                    // check is the file shared
                    if (!groups[command[1]].is_file_shared(command[1]))
                    {
                        send_message_to_client("requested file is not shared\n", "requested file is not shared\n", new_socket);
                        continue;
                    }
                    // then remove
                    vector<pair<string, pair<string, pair<string, vector<pair<string, string>>>>>> &shared_files = groups[command[1]].shared_files;
                    int found = 0;
                    for (int i = 0; i < shared_files.size(); i++)
                    {
                        if (shared_files[i].first == command[2])
                        {
                            if (shared_files[i].second.second.second.size() == 1)
                            {
                                shared_files.erase(shared_files.begin() + i);
                                found = 1;
                                break;
                            }
                            for (int j = 0; j < shared_files[i].second.second.second.size(); j++)
                            {
                                if (shared_files[i].second.second.second[j].first == session_obj.user_id)
                                {
                                    shared_files[i].second.second.second.erase(shared_files[i].second.second.second.begin() + j);
                                    found = 1;
                                    break;
                                }
                            }
                        }
                        if (found == 1)
                            break;
                    }

                    send_message_to_client("successfully stopped sharing \n", "successfully stopped sharing", new_socket);
                }
                else if (command[0] == "show_downloads")
                {
                    cout << "tracker:  show_downloads request\n";
                    if (!session_obj.is_logged_in)
                    {
                        string message = "Tracker: logIn and join the group to stop sharing\n";
                        send(new_socket, message.c_str(), message.size(), 0);
                        cout << "\tuser not loggedIn to check List of group\n";
                        continue;
                    }
                    string message = "Here is the download list:\n";

                    for (auto i : user_cred[session_obj.user_id].downloads)
                    {
                        message += i;
                        message += "\n";
                    }
                    send_message_to_client(message, "sharing the list of files that are downloaded\n", new_socket);
                }

                if (valread == 0)
                {
                    cout << "connection closed" << endl;
                    break;
                }
            }
            catch (...)
            {
                // cout << "something went wrong\n";
                send_message_to_client("Something went wrong", "something went wrong\n", new_socket);
            }
        }
    }
    // closing the connected socket
}

void establish(int PORT)
{
    // thread::id parent_id=this_thread::get_id();
    // thread t1,t2;

    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello = "Hello from server";

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) // SOCK_STREAM for TCP
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;         // for ipv4
    address.sin_addr.s_addr = INADDR_ANY; // get connection to any
    address.sin_port = htons(PORT);       // holds port number htons convert from host byte to network byte

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    vector<thread> threads;

    while (true)
    {

        if (listen(server_fd, 3) < 0)
        {
            perror("listen");
            exit(EXIT_FAILURE);
        }

        cout << "Tracker started at " << PORT << endl;

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        threads.emplace_back(thread_body_for_handling_client, new_socket, server_fd, address, addrlen, valread);
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    close(new_socket);
    // closing the listening socket
    close(server_fd);
    cout << "Tracker at port " << PORT << " closed" << endl;
}

void exit_tracker()
{
    while (true)
    {
        cout << "Enter commands: ";
        string command;
        cin >> command;
        if (command == "quit")
        {
            cout << "Exiting tracker" << endl;
            exit(0);
        }
        else if (command == "debug")
        {
            cout << "\n<<<<<<<<<<<<<<Debugging>>>>>>>>>>>>>\n";
            // just enter debug
            cout << "groups: \n";
            for (auto i : groups)
            {
                cout << "\tgroup name: " << i.first << "\n";
                cout << "\tgroup owner: " << i.second.owner << "\n";

                cout << "\tgroup members: ";
                for (auto j : i.second.members)
                {
                    cout << j << " ";
                }
                cout << "\n\tFile shared: ";
                for (auto j : i.second.shared_files)
                {
                    cout << j.first << " " << " " << j.second.first << " ";
                    for (auto k : j.second.second.second)
                    {
                        cout << k.first << " " << k.second;
                    }
                    cout << "\n";
                }
                cout << "\n\n"; // for better readability
            }
            cout << "\n\nusers:";

            for (auto i : user_cred)
            {
                cout << "\t user id:" << i.first << "\n\t password: " << i.second.password << "\n";
                // groups_joined
                cout << "\t group created= ";
                for (auto j : i.second.groups_created)
                {
                    cout << " " << j << " "; // group name
                }
                cout << "\n";

                cout << "\t group joined= ";
                for (auto j : i.second.groups_joined)
                {
                    cout << " " << j << " "; // group name
                }
                cout << "\n";

                cout << "\t file sharing= ";
                for (auto j : i.second.file_sharing)
                {
                    cout << " " << j << " "; // group name
                }
                cout << "\n\n";
            }

            cout << "pending requests\n";
            for (auto i : requests_client)
            {
                cout << i.first << " : ";
                for (auto j : i.second)
                {
                    cout << j << " ";
                }
                cout << "\n"; // for better readability
            }
            cout << "\n";
            cout << "group requests\n";
            for (auto i : requests_group)
            {
                cout << i.first << " : ";
                for (auto j : i.second)
                {
                    cout << j << " ";
                }
                cout << "\n"; // for better readability
            }
            cout << "\n<<<<<<<<<<<<<<Ends Debugging>>>>>>>>>>>>>\n";
        }
        else
            cout << "command not found\n";
    }
}

int main(int argc, char const *argv[])
{

    // to run ./a.out trackerfile.txt 1
    if (argc == 3)
    {

        // handles error like is it file etc
        thread th1, th2, th3, th4, th5;

        if (stoi(argv[2]) <= number_of_trackers) // handle stoi
        {
            if (stoi(argv[2]) == 1)
            {
                th1 = thread(establish, PORT1);
            }
            else if (stoi(argv[2]) == 2)
            {
                th2 = thread(establish, PORT2);
            }
            else if (stoi(argv[2]) == 3)
            {
                th3 = thread(establish, PORT3);
            }
            else if (stoi(argv[2]) == 4)
            {
                th4 = thread(establish, PORT4);
            }
        }
        else
        {
            cout << "only " << number_of_trackers << " available";
            exit(1);
        }

        th5 = thread(exit_tracker);

        if (th1.joinable())
            th1.join();
        if (th2.joinable())
            th2.join();
        if (th3.joinable())
            th3.join();
        if (th4.joinable())
            th4.join();
        if (th5.joinable())
            th5.join();
    }
    else
    {
        cout << "Wrong number of arguments";
        exit(1);
    }

    // cout << "\nclosing";
    return 0;
}
