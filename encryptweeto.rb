require 'twitter'
require 'tty'
require 'json'
require 'pp'
require 'base64'
require 'listen'


#authenticate with the Twitter API service
client = Twitter::REST::Client.new do |config|
  config.consumer_key        = ENV["CONSUMER_KEY"]
  config.consumer_secret     = ENV["CONSUMER_SECRET"]
  config.access_token        = ENV["ACCESS_TOKEN"]
  config.access_token_secret = ENV["ACCESS_SECRET"]
end

#load the groups and parse the json into a hash
json = File.read('groups.json')
hash = JSON.parse(json)        

#create an AES256-CBC cipher using the OpenSSL library and set to encrypt mode
#using symmetric encryption so that we only need the one key - much easier to manage
cipher = OpenSSL::Cipher::AES256.new :CBC
cipher.encrypt

#create a new prompt
prompt = TTY::Prompt.new
#keep looping
while(true)
    #needs input
    ans = prompt.ask("What command would you like to run? >", required: true)
    #pattern matching of mkgrp -g [groupname]
    if(ans =~ /mkgrp -g ([\w\s]*)/)
        regex = /mkgrp -g ([\w\s]*)/
        grpname = regex.match(ans)[1]
        #group name is the first match
        #generate initialisation vector and key
        #use Base64 to encode and ensure you don't end up with ??? characters
        iv =  Base64.encode64(cipher.random_iv)
        key = Base64.encode64(cipher.random_key)
        #store in the hash and write to the json, no users in the group yet
        hash[grpname] = Hash.new
        hash[grpname]["Key"] = key
        hash[grpname]["IV"] = iv
        hash[grpname]["Users"] = []

        File.open('groups.json', 'w') {|file| file.write(hash.to_json)}

    #makes group with specified key and initalisation vector
    elsif(ans =~ /mkgrp -g ([\w\s]*) -k (.*) -i (.*)/)
        regex = /mkgrp -g ([\w\s]*)-k (.*) -i (.*)/
        
        #fancy pattern matching
        grpname = regex.match(ans)[1]
        iv = Base64.encode64(regex.match(ans)[2])
        iv = Base64.encode64(regex.match(ans)[3])
        hash[grpname] = Hash.new
        hash[grpname]["Key"] = key
        hash[grpname]["IV"] = iv
        hash[grpname]["Users"] = []

        File.open('groups.json', 'w') {|file| file.write(hash.to_json)}

    #if you want to remove a group, it gets deleted from the hash and overwrites the file
    elsif(ans =~ /rmgrp -g ([\w\s]*)/)
        regex = /rmgrp -g ([\w\s]*)/
        grpname = regex.match(ans)[1]
        hash.delete(grpname)

        File.open('groups.json', 'w') {|file| file.write(hash.to_json)}
        
    #lists all the groups
    elsif(ans =~ /lsgrp/)
        puts hash.keys
    
    #pretty prints everything in the hash
    #isn't really that pretty
    elsif(ans =~ /lsall/)
        pp hash

    #add a user to the group
    elsif(ans =~ /adduser -u (@[\w]*) -g ([\w\s]*)/)
        regex = /adduser -u (@[\w]*) -g ([\w\s]*)/
        username = regex.match(ans)[1]
        grpname = regex.match(ans)[2]
        #push their name onto the array of users
        hash[grpname]['Users'] << username
        
        File.open('groups.json', 'w') {|file| file.write(hash.to_json)}
        
        #send the new user a DM with the key and initialisation vector
        #also the group name, which isn't really needed but it helps make sure they're in the right group
        text = "The key is #{hash[grpname]["Key"]}"\
        "The iv is #{hash[grpname]["IV"]}" \
        "The group is called #{grpname}"
        client.create_direct_message(username, text)


    #removes a user, generates a new symmetric key and iv and sends it to everyone still in the group
    elsif(ans =~ /rmuser -u (@[\w]*) -g ([\w\s]*)/)
        regex = /rmuser -u (@[\w]*) -g ([\w\s]*)/
        username = regex.match(ans)[1]
        grpname = regex.match(ans)[2]
        hash[grpname]["Users"].delete(username)

        iv =  Base64.encode64(cipher.random_iv)
        key = Base64.encode64(cipher.random_key)

        hash[grpname]["Key"] = key
        hash[grpname]["IV"] = iv

        File.open('groups.json', 'w') {|file| file.write(hash.to_json)}
        hash[grpname]["Users"].each do |user|
            text = "The key is #{hash[grpname]["Key"]}"\
                "The iv is #{hash[grpname]["IV"]}" \
                "The group is called #{grpname}"
            client.create_direct_message(user, text)
        end
        
    #uses the key and iv of that group to encrypt the ciphertext, again encoding it to avoid weird symbols
    #concatenating the final so it encrypts properly
    #sends out an encrypted tweet from the client
    elsif(ans =~ /tweet -t ([\w\s]*) -g ([\w\s]*)/)
        regex = /tweet -t ([\w\s]*) -g ([\w\s]*)/
        text = regex.match(ans)[1]
        grpname = regex.match(ans)[2]
        
        key = hash[grpname]["Key"]
        iv = hash[grpname]["IV"]
        
        cipher.key = key
        cipher.iv = iv
        ciphertext = Base64.encode64(cipher.update(text) + cipher.final)

        client.update(ciphertext)
        

    #sends an encrypted dm to a specific user using the key and iv from a group
    #very similar to above
    elsif(ans =~ /dm -t ([\w\s]*) -u (@[\w]*) -g ([\w\s]*)/)
        regex = /dm -t ([\w\s]*) -u (@[\w]*) -g ([\w\s]*)/
        
        text = regex.match(ans)[1]
        user = regex.match(ans)[2]
        grpname = regex.match(ans)[3]
        
        key = hash[grpname]["Key"]
        iv = hash[grpname]["IV"]
        
        cipher.key = key
        cipher.iv = iv
        ciphertext = Base64.encode64(cipher.update(text) + cipher.final)

        client.create_direct_message(user, ciphertext)

    #decodes text using the key and iv from a given group
    elsif(ans =~ /decode -t (.*) -g ([\w\s]*)/)
        regex = /decode -t (.*) -g ([\w\s]*)/
        #need to use the original encoding to get the original text
        text = Base64.decode64(regex.match(ans)[1])
        grpname = regex.match(ans)[2]
        
        key = hash[grpname]["Key"]
        iv = hash[grpname]["IV"]
        
        #create a new OpenSSL cipher and set it to decrypt mode
        decipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
        decipher.decrypt
        decipher.key = key
        decipher.iv = iv
        puts decipher.update(text) + decipher.final + " is the decoded text"

    #decodes text using a specific key and iv
    elsif(ans =~ /decode -t (.*) -k (.*) -i (.*)/)
        regex = /decode -t (.*) -k (.*) -i (.*)/
        text = Base64.decode64(regex.match(ans)[1])
        key = regex.match(ans)[2]
        iv = regex.match(ans)[3]
        
        decipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
        decipher.decrypt
        decipher.key = key
        decipher.iv = iv
        
        puts decipher.update(text) + decipher.final + " is the decoded text"
        

    #if it is q or quit then exit the program
    elsif(ans =~ /q/)
        puts "Shutting down..."
        exit(0)
   
    #otherwise bombard the user with help text
    else
        puts "The following are valid commands"
        puts "->mkgrp -g [groupname] -- makes a new group and auto generates keys for it"
        puts "->rmgrp -g [groupname] -- deletes a group"
        puts "->mkgrp -g [groupname] -k [key] -i [initialisation vector] -- makes a group with specified keys"
        puts "->lsgrp -- lists groups"
        puts "->lsall -- prints out all groups and their information"
        puts "->adduser -u [user] -g [groupname] -- adds a user to a group and sends them the key they need"
        puts "->rmuser -u [user] -g [groupname] -- removes a user from a group,
                 changes the keys and sends the new one to all members of the group"
        puts "->tweet -t [text] -g [groupname] -- sends a tweet using the key from the specified group"
        puts "->decode -t [text] -g [groupname] -- decodes text using the key and iv of the specified group"
        puts "->decode -t [text] -k [key] -i [initialisation vector] -- decodes text with the given key and iv"
        puts "->dm -t [text] -u [user] -g [groupname] -- sends a dm to the specified user using the key from the specified group"
        puts "->quit -- exits management console"
        puts "->help -- lists commands"
    end

end


