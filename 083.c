//@Deepansh Lodhi(2018ucs0083)

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#define MAX_INPUT_SIZE 1024
#define MAX_TOKEN_SIZE 64
#define MAX_NUM_TOKENS 64

struct Node
{
    int data;
    char *command;
    char *first;
    int status;//status : 0 correspond terminated and 1 corresponds running
    int pid;
    struct Node *next;
    struct Node *prev;
};

struct Node *head=NULL;
struct Node *tail=NULL;

// append function: to append node in the linked list
void append(struct Node** head_ref,struct Node** tail_ref,char **tokens,int status,int pid) 
{ 
    struct Node* new_node = (struct Node*) malloc(sizeof(struct Node)); 
    new_node->command = malloc(sizeof(char*));
    new_node->first = malloc(sizeof(char*));
    struct Node *last = *head_ref;  
    char *s;
    s=malloc(sizeof(char*));
    int i=0;
    while(tokens[i]!=NULL){
        strcat(s,tokens[i]);
        strcat(s," ");
        i++;
    }
    strcpy(new_node->command,s);
    free(s);
    strcpy(new_node->first,tokens[0]);
    new_node->pid=pid;
    new_node->status=status;
    new_node->next = NULL; 
    if (*head_ref == NULL) 
    { 
        new_node->data=1;
       *head_ref = new_node; 
       new_node->prev=NULL;
       *tail_ref=new_node;
       return; 
    } 
    while (last->next != NULL) 
        last = last->next; 
    new_node->data=last->data+1;
    last->next = new_node; 
    new_node->prev = last;
    *tail_ref=new_node;

    return; 
} 

//tokenizes string
char **tokenize(char *line)
{
    char **tokens = (char **)malloc(MAX_NUM_TOKENS * sizeof(char *));
    char *token = (char *)malloc(MAX_TOKEN_SIZE * sizeof(char));
    int i, tokenIndex = 0, tokenNo = 0;

    for (i = 0; i < strlen(line); i++)
    {

        char readChar = line[i];

        if (readChar == ' ' || readChar == '\n' || readChar == '\t')
        {
            token[tokenIndex] = '\0';
            if (tokenIndex != 0)
            {
                tokens[tokenNo] = (char *)malloc(MAX_TOKEN_SIZE * sizeof(char));
                strcpy(tokens[tokenNo++], token);
                tokenIndex = 0;
            }
        }
        else
        {
            token[tokenIndex++] = readChar;
        }
    }

    free(token);
    tokens[tokenNo] = NULL;
    return tokens;
}



// history full
void printList(struct Node *node) 
{ 
  while (node != NULL) 
  { 
     printf("%d", node->data);
     printf(" %s\n", node->command); 
     node = node->next; 
  } 
}
// HISTn
void fromLast(struct Node *node,int key)
{
    for(int i=1;i < key+1;i++){
        if(node!=NULL){
            printf("%d %s\n",i,node->command); 
            node=node->prev;  
        }
        else{
            break;
        }
    }
}

// history brief
void printBrief(struct Node *node) 
{ 
  while (node != NULL) 
  { 
     printf("%d", node->data);
     printf(" %s\n", node->first); 
     node = node->next; 
  } 
}

pid_t bg_pgid; // process group id for background process

void signalHandler(int signum)
{
    // puts("\nTo EXIT SHELL use : STOP");
    // puts("Press ENTER key");
}

// prints pid of all the the process that are executed till now
void pid_all(struct Node* node){
  while (node != NULL) 
  { 
     if(node->pid!=0){
     printf("command name: %s || process id %d\n", node->command,node->pid); 
     
    // puts("hello");
     }
     node = node->next; 
  } 
  return;
}

void pid_current(struct Node* node){
  while (node != NULL) 
  { 
     if(node->status==1){
     printf("command name: %s || process id %d\n", node->command,node->pid); 
     
     }
     node = node->next; 
  }     
  return;
}
char* changeStatus(struct Node* node , int pid){
    while(node->pid!=pid){
        node=node->next;
    }
    node->status=0;
    char *name = node->command;
    return name;
}

// Handles SIGCHLD for parent
void sigchldHandler(int signum) {
    int status;
    pid_t back;
    back = waitpid(-1, &status, WNOHANG);
    // printf("%d",back);
    if(back != 0){//if back!=0 means background process
    char *name = changeStatus(head,back);//changing running status of background process to terminated
    printf("\nProcess ID: %d running command: %s exited\n",back,name);
    }
}

void exec_builtin(char **tokens)
{
    signal(SIGINT, signalHandler);
    pid_t child_pid = fork();
    if (child_pid == -1)
    {
        printf("Could not fork.\n");
    }
    else
    {
        if (child_pid>0)
        {   
            append(&head,&tail,tokens,0,child_pid);
            wait(NULL);
        }
        else
        {
            int ret = execvp(tokens[0], tokens);
            if (ret = -1)
                printf("Could not find command: %s\n", tokens[0]);
                exit(0);
        }
    }
}
// &
void exec_background(char ** tokens) {
    pid_t child_pid = fork();

        if(child_pid == -1) {
            printf("Could not fork.\n");
        }
        else {
            if(child_pid>0) {
                //appending background process details in linked list with status corresponding to running
                append(&head,&tail,tokens,1,child_pid);
            }
            else if (child_pid==0){
                setpgid(getpid(), bg_pgid); 
                // Puts background processes in background process group
                // dumping backgroud process output
                int fd = open("/dev/null", O_WRONLY); 
                dup2(fd, 1); 
                dup2(fd, 2); 
                close(fd);
                int ret = execvp(tokens[0], tokens);
                if(ret == -1){
                    // printf("%d\n", parallel);
                    printf("Could not find command: %s\n", tokens[0]);
                    exit(0);
                }
                }
        }
        return;
}
// execute redirect
void exec_redirect(char *tokens[],int back)
{
    signal(SIGINT, signalHandler);
    pid_t child_pid = fork();
    if (child_pid == -1)
    {
        printf("Could not fork.\n");
    }
    else
    {
        if (child_pid>0)
        {
            if(back==0){
                // append(&head,&tail,tokens,0,child_pid);
                wait(NULL);
            }
        }
        else
        {
            if(back==1){
                setpgid(getpid(), bg_pgid); 
                // Puts background processes in background process group
                // dumping backgroud process output
                int fd = open("/dev/null", O_WRONLY); 
                dup2(fd, 1); 
                dup2(fd, 2); 
                close(fd);
                int ret = execvp(tokens[0], tokens);
                if(ret == -1){
                    // printf("%d\n", parallel);
                    printf("Could not find command: %s\n", tokens[0]);
                    exit(0);
                }
            }
            else{
                // puts("inside");
                int ret = execvp(tokens[0], tokens);
                if (ret = -1)
                    printf("Could not find command: %s\n", tokens[0]);
                exit(0);
            }
        }
    }
}

// redirection
void redirect(char ** tokens,int t){
    char *command[20]={NULL};
    int tmpin=dup(0);
    int tmpout = dup (1);
    int fdin;
    int fdout;
    int j=0,count=0;
    int flag=0;
    while(tokens[j]!=NULL){
        if(strcmp(tokens[j],"<")==0 || strcmp(tokens[j],"|")==0){
            count+=1;
        }
        if(strcmp(tokens[j],">")==0){
            if(tokens[j+1]==NULL){
                puts("Wrong number of arguments");
                puts("Usage:    |command| > file_name");
                return;
            }
            else if(tokens[j+2]!=NULL)
            {   
                puts("Excess number of argumenrs");
                puts("Usage:    |command| > file_name");
                return;
            }
            flag =j;
        }
        j++;
    }
    if (count==0){
        fdout = open(tokens[flag+1], O_WRONLY|O_CREAT, 00777); // File to write to
        dup2(fdout, 1); // Change file descriptor of file to 1
        free(tokens[flag]);
        free(tokens[flag+1]);
        tokens[flag] = NULL;
        exec_redirect(tokens, 0);
        dup2(tmpout, 1); // Restore STDOUT file descriptor
        return;
    }
    int i=0;
    while(tokens[i]!=NULL){
        // if(strcmp(tokens[i+2],">")==0){
        if(flag==i+2){
            fdout = open(tokens[i+3],O_WRONLY|O_CREAT, 00777);
                // Change file descriptor of file to 1
            // dup2(tmpout, 1); // Restore STDOUT file descriptor
        }
        // }
        else{
                fdout=dup(tmpout);
            }
        dup2(fdout, 1);
        if(strcmp(tokens[i],"<")==0){
            if(tokens[i+2]!=NULL && strcmp(tokens[i+2],">")!=0 && strcmp(tokens[i+2],"|")!=0){
                puts("Could not run the command. Wrong number of argument.");
                puts("Usage:    |command| < file_name");
                close(fdout);
                dup2(tmpout,1); // Restore STDOUT file descriptor
                return;
            }
            fdin = open(tokens[i+1],O_RDONLY); //open File to read
            // puts("hello");
            dup2(fdin, 0); // Change file descriptor of file to 0
            // puts("this is bad");
            close(fdin);
            for(int k=0;k<i;k++){
                command[k]=tokens[k];
            }
            command[i]=NULL;
            exec_redirect(command,0);
            dup2(tmpin, 0); // Restore STDIN file descriptor
            close(fdout);
            dup2(tmpout,1); // Restore STDOUT file descriptor
        }
        if(strcmp(tokens[i],"|")==0){
            
                int fdpipe[2];
                pipe(fdpipe);

                // close(fdpipe[0]);
            
                for(int k=0;k<i;k++){
                    command[k]=tokens[k];
                }
                command[i]=NULL;
                // puts("first");

                fdout=fdpipe[1];// pipe write
                dup2(fdout,1);
                exec_redirect(command,0);//first command
                fdin = fdpipe[0];
                dup2(fdin, 0); //copy fdin to STDIN file descriptor
                close(fdout);
                dup2(tmpout,1);
                // puts("second coomad");
                // dup2(tmpout,1); // Restore STDOUT file descriptor 
                command[0]=tokens[i+1];
                command[1]=NULL;
                exec_redirect(command,0);
                dup2(tmpin,0);
                // puts("out");
                close(fdin);
                close(fdout);
            
        }


        i++;
    }

}
// EXEC index_number
void execute(struct Node *node,int key)
{
    if(node!=NULL){
        for(int i=0; i=key; i++){
            if (node->data==key){
                char **tokens = tokenize(node->command);
                exec_builtin(tokens);  
                break;          
            }
            else if(node->next==NULL){
                printf("Command not found in history.\nHistory exist upto index number %d\n",node->data);
                  break;
            }
            node =node->next;
        }
    }
    else{
        puts("Could not run command: History does not exist");
    }
    return;
}
// !HISTn
void execfromlast(struct Node *node,int key)
{   //if linked list is not empty
    if(node!=NULL){
        for(int i=1;i < key+1;i++){
            if(node!=NULL){
                // printf("%d %s\n",i,node->command); 
                
                if(i==key){
                    char **tokens = tokenize(node->command);
                    exec_builtin(tokens); 
                    break;
                }
            }
            else{
                printf("Command not found in history.\nHistory exist upto index number %d\n",i);
                break;
            }
            node=node->prev; 
        }
    }
    else{//if linked list is empty means no history
    puts("Could not run command: History does not exist");
    }
    return;
}
// Change directory command;
void change_dir(char** tokens) { 
    if(tokens[1] == NULL)
    {
        printf("Provide directory name\n");
        return;
    }
    else if(tokens[2] != NULL) {
        printf("Too many arguments || USAGE: cd <directory_name>\n");
        return;
    }
    int ret = chdir(tokens[1]);
    if(ret == -1){
        printf("Error: Directory not found\n");
        return;
    }
    return;
}


int main(int argc, char const *argv[])
{
    char line[MAX_INPUT_SIZE];
    char bline[MAX_INPUT_SIZE];
    char **tokens;
    int i;

    printf("\nWELCOME TO INTERACTIVE SHELL\n");

    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL);
    else
    printf("getcwd() error"); 

    pid_t bg_while = fork(); // Set up a background loop; leader of background process group

    if(bg_while == -1) {
            printf("Could not fork.\n");
        }
        else {
            if(!bg_while) {
                setpgid(getpid(), getpid());
                while(1) {;}
            }
            else {
                bg_pgid = bg_while;
            }
        }

    pid_t parent_pid = getpid();
    setpgid(parent_pid, parent_pid);

    signal(SIGINT, signalHandler);
    signal(SIGTSTP,signalHandler);
    signal(SIGCHLD, sigchldHandler);
    puts("***********************************************************************************");
    puts("USE COMMANDS:");
    puts("\nSTOP              : to exit from shell");
    puts("HISTORY BRIEF     : to get command list without arguments ");
    puts("HISTORY FULL      : to get history of commands with arguments");
    puts("EXEC <command>    : to execute command");
    puts("EXEC <command-index-number>   :to execute command with given index-number ");
    puts("HISTn             : prints last n commands from history");
    puts("!HISTn            : run last nth command from history");
    puts("<command>&        : to run process in background");
    puts("pid               : to get pid of shell");
    puts("pid current       : to get list of the pids of the processes that are currently active");
    puts("pid all           : prints the list of pids of all commands that were executed so far by the shell (including the currently executing processes)");
    puts("***********************************************************************************");
    // printf("Deepansh@iitjammu:");    

    while (1)
    {
        printf("\nDeepansh@iitjammu:");
        char cwdnew[1024];
        
        if (getcwd(cwdnew, sizeof(cwdnew)) != NULL){
            int cn=strncmp(cwd,cwdnew,sizeof(cwd));
            if(cn==0){
                printf("~> ");
            }
            else if (cn>0)
            {
                printf("%s> ",cwdnew);
            }
            else{
                printf("~%s> ",&cwdnew[strlen(cwd)]);
            }
            
            // printf("%s\n", cwdnew);
        }
        else{
        printf("getcwd() error"); 
        }
        bzero(line, MAX_INPUT_SIZE);
        bzero(bline, MAX_INPUT_SIZE);

        // char buf1[MAX_INPUT_SIZE];
        fgets(line, MAX_INPUT_SIZE, stdin);
        // checking background process

        if (line[strlen(line)-2]=='&')
        {
            puts("starting background process");
            strcat(strncpy(bline,line,strlen(line)-2),"\n");
            // puts(bline);
            tokens=tokenize(bline);
            exec_background(tokens);
        }//if not background call then check for  foreground commands
        else
        {
        tokens = tokenize(line);
        int j=0;
        while(tokens[j]!=NULL){
            if(strcmp(tokens[j],"<")==0 || strcmp(tokens[j],">")==0 || strcmp(tokens[j],"|")==0){
                append(&head,&tail,tokens,0,0);
                redirect(tokens,1);
                for (int i = 0; tokens[i] != NULL; i++)
                {
                    free(tokens[i]);
                }
                free(tokens); 
                continue;  
            }     
            j++;    
        }
        // printf("%s",tokens[0]);
        if (tokens[0] == NULL)
        {
            printf("\n");
            continue;
        }
        if(strcmp(tokens[0],"STOP")==0){
            // printf("stop called");
            
            // _exit(1);
            if(tokens[1] != NULL) { // Check format for exit
            printf("Excess arguments:\n");
            puts("Usage: STOP");
            }
            else 
            {
                puts("exiting normally");
                killpg(bg_pgid, SIGINT); // Kill background processes if "stop" command
                exit(0);
            }
        }
        else if(strcmp(tokens[0],"cd")==0){
            change_dir(tokens);
            append(&head,&tail,tokens,0,0);
        }
        else if (strcmp(tokens[0],"pid")==0)    
        {
            if(tokens[1]==NULL){
            printf("%d\n",getpid());
            append(&head,&tail,tokens,0,0);
            }
            else if(strcmp(tokens[1],"current")==0 && tokens[2]==NULL){
                append(&head,&tail,tokens,0,0);
                pid_current(head);
                
            }
            else if(strcmp(tokens[1],"all")==0  && tokens[2]==NULL){
                append(&head,&tail,tokens,0,0);
                pid_all(head);
                
            }
            else{
                puts("invalid command");
                append(&head,&tail,tokens,0,0);
            }
        }  
        else if(strcmp(tokens[0],"HISTORY")==0){
            if (tokens[1]==NULL)
                {
                    printf("PROVIDE VALID COMMAND\n");
                }            
            else if(strcmp(tokens[1],"BRIEF")==0 && tokens[2]==NULL){
                append(&head,&tail,tokens,0,0);
                printBrief(head);
                
            }
            else if ((strcmp(tokens[1],"FULL")==0) && tokens[2]==NULL)
            {
                append(&head,&tail,tokens,0,0);
                printList(head);
                
            }  
            else{
                puts("INVALID COMMAND");
                append(&head,&tail,tokens,0,0);
            }
        }
        else if(strcmp(tokens[0],"EXEC")==0)
        {
            // puts("exec inside");
            // exec_builtin(&tokens[1]);
            if (tokens[1]==NULL)
            {
                append(&head,&tail,tokens,0,0);
                puts("PROVIDE COMMAND TO EXECUTE");
                
            }
             // char *a= tokens[1];d
            else if (tokens[1]!=NULL && tokens[2]==NULL)
            {
                if(atoi(tokens[1])==0){
                    exec_builtin(&tokens[1]);
                }                  
                else if(atoi(tokens[1])>0)
                {   
                    
                    execute(head,atoi(tokens[1]));
                    // append(&head,&tail,tokens,0,parent_pid);
                    }  
                else {
                    append(&head,&tail,tokens,0,0);
                    puts("EXCESS number of arguments");                

                }
            }
        }

        else if (strncmp("HIST",tokens[0],4)==0)
        {
            if(atoi(&tokens[0][4])!=0 && tokens[1]==NULL){
                
                append(&head,&tail,tokens,0,0);
                fromLast(tail,atoi(&tokens[0][4]));               
            }
            else{
                // printf("%s",&tokens[0][4]);
                puts("Command not found");
                append(&head,&tail,tokens,0,0);
            }            
        }
        else if (strncmp("!HIST",tokens[0],5)==0)
        {
            if(atoi(&tokens[0][5])!=0 && tokens[1]==NULL){
                execfromlast(tail,atoi(&tokens[0][5]));                
            }
            else{
                puts("Command not found");
                append(&head,&tail,tokens,0,0);
            }
        }        
        else{
            exec_builtin(tokens);
        }
        }
        // Freeing the allocated memory
        // printf("free memory");
        for (i = 0; tokens[i] != NULL; i++)
        {
            free(tokens[i]);
            // printf("freed %s",tokens[i]);
        }
        free(tokens);
    }    
    return 0;
}