#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int bk=1;
int bTag=1;
char s[5000];
int nc,tis;
FILE *filePointer;

struct Len{
    int len, tag;
    Len(int len,int tag){
        this->len=len;
        this->tag=tag;
    }
};

struct TLV{
    TLV() {}
    char sig1[50],sig2[50];
};

struct TLV2{
    TLV2() {}
    char sig1[50],sig2[5000];
};

struct SignatureAlgorithm{
    TLV alg;
    TLV param;
};

struct SubjectPublicKey{
    TLV alg;
    TLV param;
    TLV2 pKey;
};

struct SignatureArray{
    char sig1[50],sig2[50];
}sA[7],is[6];

struct SignatureValue{
    TLV2 sigV;
};

struct TbsCertificate{
    TLV version;
    TLV serialNumber;
    struct SignatureAlgorithm signature;
    struct SignatureArray issuer[6];
    TLV validity[2];
    struct SignatureArray subject[6];
    struct SubjectPublicKey SubjectPublicKeyInfo;
    TLV issuerUniqueID;
    TLV subjectUniqueID;
    TLV extensions;
};

struct x509Cer{
    struct TbsCertificate cat;
    struct SignatureAlgorithm casa;
    struct SignatureValue casv;
}caCer;

// bind OID
void sAfill(){
    strcpy(sA[0].sig1,"1.2.840.10040.4.1");
    strcpy(sA[0].sig2,"DSA");
    strcpy(sA[1].sig1,"1.2.840.10040.4.3");
    strcpy(sA[1].sig2,"sha1DSA");
    strcpy(sA[2].sig1,"1.2.840.113549.1.1.1");
    strcpy(sA[2].sig2,"RSA");
    strcpy(sA[3].sig1,"1.2.840.113549.1.1.2");
    strcpy(sA[3].sig2,"md2RSA");
    strcpy(sA[4].sig1,"1.2.840.113549.1.1.3");
    strcpy(sA[4].sig2,"md4RSA");
    strcpy(sA[5].sig1,"1.2.840.113549.1.1.4");
    strcpy(sA[5].sig2,"md5RSA");
    strcpy(sA[6].sig1,"1.2.840.113549.1.1.5");
    strcpy(sA[6].sig2,"sha1RSA");
}

// bind RDN
void isFill(){
    strcpy(is[0].sig1,"2.5.4.6");
    strcpy(is[0].sig2,"Country ");
    strcpy(is[1].sig1,"2.5.4.8");
    strcpy(is[1].sig2,"Sate or province name ");
    strcpy(is[2].sig1,"2.5.4.7");
    strcpy(is[2].sig2,"Locality ");
    strcpy(is[3].sig1,"2.5.4.10");
    strcpy(is[3].sig2,"Organization name ");
    strcpy(is[4].sig1,"2.5.4.11");
    strcpy(is[4].sig2,"Organizational Unit name ");
    strcpy(is[5].sig1,"2.5.4.3");
    strcpy(is[5].sig2,"Common Name ");
}

// Gets the contiguous bytecode (string) from the file and assigns it to the string s
void bitFill(int dd){
    strcpy(s,"");
    for(int i=0;i<dd;i++){
        unsigned char tl=fgetc(filePointer);
        int d=tl;
        char tsig2[10];
        sprintf(tsig2,"%02x",d);
        strcat(s,tsig2);
    }
}


/**
 * Switch structure, which binds the serial number of each field of the certificate structure calling TLV function 
 * with the content of the certificate structure, and populates the ca_cer structure
 * @Author   Nino Lau
 * @DateTime 2018-12-16T17:26:36+0800
 */
void fill(int n){

    switch(n){
        
        case 4:
            strcpy(caCer.cat.version.sig1,"\nversion:\t");
            if(strcmp(s,"0")==0)   strcpy(s,"v1");
            else if(strcmp(s,"1")==0)   strcpy(s,"v2");
            else    strcpy(s,"v3");
            strcpy(caCer.cat.version.sig2,s);
            break;
        
        case 5:
            strcpy(caCer.cat.serialNumber.sig1,"\nserialNumber:\t");
            strcpy(caCer.cat.serialNumber.sig2,s);
            break;
        
        case 7:
            strcpy(caCer.cat.signature.alg.sig1,"\nname of alg of signature:\t");
            for(int i=0;i<7;i++){
                if(strcmp(s,sA[i].sig1)==0){
                    strcpy(caCer.cat.signature.alg.sig2,sA[i].sig2);
                    break;
                }
            }
            break;
        
        case 8:
            strcpy(caCer.cat.signature.param.sig1,"\nparam of signature:\t");
            strcpy(caCer.cat.signature.param.sig2,s);
            break;
        
        case 12:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.issuer[i].sig1,is[i].sig2);
                    strcat(caCer.cat.issuer[i].sig1,"of issuer:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 13:
            strcpy(caCer.cat.issuer[tis].sig2,s);
            break;
        
        case 16:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.issuer[i].sig1,is[i].sig2);
                    strcat(caCer.cat.issuer[i].sig1,"of issuer:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 17:
            strcpy(caCer.cat.issuer[tis].sig2,s);
            break;
        
        case 20:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.issuer[i].sig1,is[i].sig2);
                    strcat(caCer.cat.issuer[i].sig1,"of issuer:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 21:
            strcpy(caCer.cat.issuer[tis].sig2,s);
            break;
        
        case 24:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.issuer[i].sig1,is[i].sig2);
                    strcat(caCer.cat.issuer[i].sig1,"of issuer:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 25:
            strcpy(caCer.cat.issuer[tis].sig2,s);
            break;
        
        case 28:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.issuer[i].sig1,is[i].sig2);
                    strcat(caCer.cat.issuer[i].sig1,"of issuer:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 29:
            strcpy(caCer.cat.issuer[tis].sig2,s);
            break;
        
        case 32:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.issuer[i].sig1,is[i].sig2);
                    strcat(caCer.cat.issuer[i].sig1,"of issuer:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 33:
            strcpy(caCer.cat.issuer[tis].sig2,s);
            break;
        
        case 35:
            strcpy(caCer.cat.validity[0].sig1,"the begin of validity:\t ");
            strcpy(caCer.cat.validity[0].sig2,s);
            break;
        
        case 36:
            strcpy(caCer.cat.validity[1].sig1,"the end of validity:\t ");
            strcpy(caCer.cat.validity[1].sig2,s);
            break;
        
        case 40:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.subject[i].sig1,is[i].sig2);
                    strcat(caCer.cat.subject[i].sig1,"of subject:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 41:
            strcpy(caCer.cat.subject[tis].sig2,s);
            break;
        
        case 44:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.subject[i].sig1,is[i].sig2);
                    strcat(caCer.cat.subject[i].sig1,"of subject:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 45:
            strcpy(caCer.cat.subject[tis].sig2,s);
            break;
        
        case 48:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.subject[i].sig1,is[i].sig2);
                    strcat(caCer.cat.subject[i].sig1,"of subject:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 49:
            strcpy(caCer.cat.subject[tis].sig2,s);
            break;
        
        case 52:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.subject[i].sig1,is[i].sig2);
                    strcat(caCer.cat.subject[i].sig1,"of subject:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 53:
            strcpy(caCer.cat.subject[tis].sig2,s);
            break;
        
        case 56:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.subject[i].sig1,is[i].sig2);
                    strcat(caCer.cat.subject[i].sig1,"of subject:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 57:
            strcpy(caCer.cat.subject[tis].sig2,s);
            break;
        
        case 60:
            for(int i=0;i<6;i++){
                if(strcmp(s,is[i].sig1)==0){
                    strcpy(caCer.cat.subject[i].sig1,is[i].sig2);
                    strcat(caCer.cat.subject[i].sig1,"of subject:\t");
                    tis=i;
                    break;
                }
            }
            break;
        
        case 61:
            strcpy(caCer.cat.subject[tis].sig2,s);
            break;
        
        case 64:
            strcpy(caCer.cat.SubjectPublicKeyInfo.alg.sig1,"\nname of alg of SubjectPublicKey:\t");
            for(int i=0;i<7;i++){
                if(strcmp(s,sA[i].sig1)==0){
                    strcpy(caCer.cat.SubjectPublicKeyInfo.alg.sig2,sA[i].sig2);
                    break;
                }
            }
            break;
        
        case 65:
            strcpy(caCer.cat.SubjectPublicKeyInfo.param.sig1,"\nparam of alg of SubjectPublicKey:\t");
            strcpy(caCer.cat.SubjectPublicKeyInfo.param.sig2,s);
            break;
        
        case 66:
            strcpy(caCer.cat.SubjectPublicKeyInfo.pKey.sig1,"\nSubjectPublicKey:\t");
            strcpy(caCer.cat.SubjectPublicKeyInfo.pKey.sig2,s);
            break;
        
        case 69:
            strcpy(caCer.casa.alg.sig1,"\nname of signatureAlgorithm:\t");
            for(int i=0;i<7;i++){
                if(strcmp(s,sA[i].sig1)==0){
                    strcpy(caCer.casa.alg.sig2,sA[i].sig2);
                    break;
                }
            }
            break;
        
        case 70:
            strcpy(caCer.casa.param.sig1,"\nparam of signatureAlgorithm:\t");
            strcpy(caCer.casa.param.sig2,s);
            break;
        
        case 71:
            strcpy(caCer.casv.sigV.sig1,"\nsigniture value:\t");
            strcpy(caCer.casv.sigV.sig2,s);
            bk=0;
            break;
    }
}

// TLV matched recursion
Len tlv(){
    if(bk==0)   return Len(1000,0);
    nc++;
    int b=1;
    unsigned char type=fgetc(filePointer);
    unsigned char len0=fgetc(filePointer);
    int len=len0;
    int lem=0;
    if(type<0xa0){
        if(type==1){
            unsigned char vc=fgetc(filePointer);
            if(vc==0)   strcpy(s,"0");
            else    strcpy(s,"1");
        }else if(type==2){
            if(len0>0x80){
                int tn2=len0-0x80;
                unsigned char tl;
                len=0;
                for(int i=0;i<tn2;i++){
                    tl=fgetc(filePointer);
                    len*=256;
                    len+=tl;
                }
            }
            bitFill(len);
        }else if(type==3){
            if(len0>0x80){
                int tn2=len0-0x80;
                unsigned char tl;
                len=0;
                for(int i=0;i<tn2;i++){
                    tl=fgetc(filePointer);
                    len*=256;
                    len+=tl;
                }
            }
            bitFill(len);
        }else if(type==4){
            if(len0>0x80){
                int tn2=len0-0x80;
                unsigned char tl;
                len=0;
                for(int i=0;i<tn2;i++){
                    tl=fgetc(filePointer);
                    len*=256;
                    len+=tl;
                }
            }
            bitFill(len);
        }else if(type==5){
            strcpy(s,"NULL");
        }else if(type==6){
            strcpy(s,"");
            int dd=len0;
            unsigned char tl=fgetc(filePointer);
            int d=tl/40;
            char tsig2[10];
            sprintf(tsig2,"%d",d);
            strcat(s,tsig2);
            strcat(s,".");
            d=tl-d*40;
            sprintf(tsig2,"%d",d);
            strcat(s,tsig2);
            for(int i=1;i<dd;i++){
                strcat(s,".");
                i--;
                int t=0;
                while(1){
                    tl=fgetc(filePointer);
                    i++;
                    int b2=0;
                    if(tl&0x80){
                        b2=1;
                    }
                    if(b2){
                         tl&=0x7f;
                    }
                    t*=128;
                    t+=tl;
                    if(!b2) break;
                }
                sprintf(tsig2,"%d",t);
                strcat(s,tsig2);
            }
        }else if(type==0x13){
            int d=len0;
            fread(s,1,d,filePointer);
            s[d]='\0';
        }else if(type==0x17||type==0x18){
            int d=len0;
            fread(s,1,d,filePointer);
            s[d]='\0';
        }else if(type==0x30||type==0x31){
            b=0;
            if(len0>0x80){
                len=0;
                len0-=0x80;
                unsigned char tl;
                for(int i=0;i<len0;i++){
                    tl=fgetc(filePointer);
                    len*=256;
                    len+=tl;
                }
            }
            int dlen=len;
            while(dlen>0){
                dlen-=tlv().len;
            }
        }else{
            printf("the cer has errors!\n");
            exit(0);
        }
    }else{
        b=0;
        lem=type-0xa0;
        if(len0>0x80){
            int tn2=len0-0x80;
            unsigned char tl;
            len=0;
            for(int i=0;i<tn2;i++){
                tl=fgetc(filePointer);
                len*=256;
                len+=tl;
            }
        }
        if(bTag){
            if(nc==67)  fseek(filePointer,len,SEEK_CUR);
            else    tlv();
        }
    }
    if(b)   fill(nc);
    return Len(len,lem);
}

void output(){
    printf("\n******* Certificate Athority Parsing *******\n");
    printf("%s%s\n",caCer.cat.version.sig1,caCer.cat.version.sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.cat.serialNumber.sig1,caCer.cat.serialNumber.sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.cat.signature.alg.sig1,caCer.cat.signature.alg.sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.cat.signature.param.sig1,caCer.cat.signature.param.sig2);
    printf("\n--------------------------------------------\n");
    printf("\nvalidity %s-%s\n",caCer.cat.validity[0].sig2,caCer.cat.validity[1].sig2);
    printf("\n--------------- ISSUER --------------------- \n%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n",caCer.cat.issuer[0].sig1,caCer.cat.issuer[0].sig2,
                caCer.cat.issuer[1].sig1,caCer.cat.issuer[1].sig2,caCer.cat.issuer[2].sig1,caCer.cat.issuer[2].sig2,
                caCer.cat.issuer[3].sig1,caCer.cat.issuer[3].sig2,caCer.cat.issuer[4].sig1,caCer.cat.issuer[4].sig2,
                caCer.cat.issuer[5].sig1,caCer.cat.issuer[5].sig2);
    printf("\n--------------------------------------------\n");
    printf("\n--------------- SUBJECT -------------------- \n%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n",caCer.cat.subject[0].sig1,caCer.cat.subject[0].sig2,
                caCer.cat.subject[1].sig1,caCer.cat.subject[1].sig2,caCer.cat.subject[2].sig1,caCer.cat.subject[2].sig2,
                caCer.cat.subject[3].sig1,caCer.cat.subject[3].sig2,caCer.cat.subject[4].sig1,caCer.cat.subject[4].sig2,
                caCer.cat.subject[5].sig1,caCer.cat.subject[5].sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.cat.SubjectPublicKeyInfo.alg.sig1,caCer.cat.SubjectPublicKeyInfo.alg.sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.cat.SubjectPublicKeyInfo.param.sig1,caCer.cat.SubjectPublicKeyInfo.param.sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.cat.SubjectPublicKeyInfo.pKey.sig1,caCer.cat.SubjectPublicKeyInfo.pKey.sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.casa.alg.sig1,caCer.casa.alg.sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.casa.param.sig1,caCer.casa.param.sig2);
    printf("\n--------------------------------------------\n");
    printf("%s%s\n",caCer.casv.sigV.sig1,caCer.casv.sigV.sig2);
    printf("\n********************************************\n");
}

int main(){
    char *filename="./CA.cer";
    filePointer=fopen(filename,"rb");
    if(filePointer==NULL){
        puts("File open fails!");
        exit(0);
    }
    sAfill();
    isFill();
    tlv();
    fclose(filePointer);
    output();
    return 0;
}