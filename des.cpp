///Md. Samshad Rahman (Network Security)

#include<bits/stdc++.h>

using namespace std;

#define si(x) scanf("%d",&x)
#define sii(x,y) scanf("%d %d",&x,&y)
#define siii(x,y,z) scanf("%d %d %d",&x,&y,&z)
#define sl(x) scanf("%lld",&x)
#define sll(x,y) scanf("%lld %lld",&x,&y)
#define slll(x,y,z) scanf("%lld %lld %lld",&x,&y,&z)
#define ss(ch) scanf("%s",ch)
#define pi(x) printf("%d",x)
#define pii(x,y) printf("%d %d",x,y)
#define pl(x) printf("%lld",x)
#define pll(x,y) printf("%lld %lld",x,y)
#define sf scanf
#define pf printf
#define pcs(x,y) printf("Case %d: %s", x, y)
#define pci(x,y) printf("Case %d: %d", x, y)
#define pcl(x,y) printf("Case %d: %lld", x, y)
#define NL printf("\n")
#define nl '\n'
#define mod 1000000007
#define FI freopen("in.txt","r",stdin)
#define FO freopen("out.txt","w",stdout)

#define FOR(i,j,k) for(int i = j; i < k; i++)
#define rep(l,n) FOR(l,0,n)
#define per(i,j,k) for(int i = j; i > k; i--)

#define PI acos(-1.0)
#define eps 1e-9

#define pb(x) push_back(x)
#define ppb() pop_back()
#define sz(x) x.size()
#define xx first
#define yy second
#define mp(a,b) make_pair(a,b)
#define ssz(a) strlen(a)

#define mem(ara,val) memset(ara,val,sizeof(ara))
#define clr(ara) mem(ara,0)
#define st(ara) mem(ara,-1)
#define all(a) a.begin(),a.end()
//cerr << "Time elapsed: " << 1.0 * clock() / CLOCKS_PER_SEC << " s.\n";

#define debug(args...) {dbg,args; cout<<endl;}

struct debugger{
    template<typename T> debugger& operator , (const T& v){
        cout<<v<<" ";
        return *this;
    }
}dbg;

typedef long long LL;
typedef vector<int> VI;
typedef pair<int,int> PII;
typedef vector< PII > VII;

int dx[] = {-1, 1, 0, 0, -1, -1, 1, 1};
int dy[] = {0, 0, 1, -1, -1, 1, -1, 1};

///=>=>=>=>=>=>=>=>=>00100<=<=<=<=<=<=<=<=<=///

/// 133457799BBCDFE7 FEDCBA0123456015
/// 0001001100110100010101110111100110011011101111001101111111100111
/// 1111111011011100101110100000000100100011010001010110000000010101

///pc1 = 56, pc2 = 48, ip = 64, eBit = 48, p = 32, ipI1 = 64

int pc1[60], leftShift[20], pc2[50], ip[70], eBit[50], p[35], ipI1[70];
int s[10][10][70];

string PT, iKey, k[20], c[20], d[20], L[20], R[20];

void print(string x, int len){
    int i = 0;
    rep(l,len){
        cout << x[l];
        i++;
        if(i >= 4){
            i = 0;
            cout << " ";
        }
    }
}

int b2d(int n){
    int num = n;
    int ret = 0;
    int base = 1;
    int tmp = num;

    while(tmp){
        int x = tmp % 10;
        tmp /= 10;
        ret += x * base;
        base *= 2;
    }
    return ret;
}

string d2b(int n){
    int arr[1000];
    int i = 0;
    while(n > 0){
        arr[i++] = n % 2;
        n /= 2;
    }

    string ret = "";
    per(l, i-1, -1) ret += (char)(arr[l] + '0');

    return ret;
}

void buildTables(){
    rep(l,56) si(pc1[l]);
    FOR(l, 1, 17) si(leftShift[l]);
    rep(l,48) si(pc2[l]);
    rep(l,64) si(ip[l]);
    rep(l,48) si(eBit[l]);
    rep(l,32) si(p[l]);
    rep(l,64) si(ipI1[l]);

    FOR(l, 1, 9)
        rep(i,4)
            rep(j,16) si(s[l][i][j]);

    rep(l,20){
        c[l] = "";
        d[l] = "";
        k[l] = "";
        L[l] = "";
        R[l] = "";
    }
}

void buildC0D0(){
    rep(l,28){
        int k = pc1[l] - 1;
        c[0] += iKey[k];
    }
    FOR(l, 28, 56){
        int k = pc1[l] - 1;
        d[0] += iKey[k];
    }
}

string shift(string x, int id){
    string ret = "";
    FOR(l, leftShift[id], sz(x)) ret += x[l];
    rep(l,leftShift[id]) ret += x[l];
    return ret;
}

void buildCD(){
    FOR(l, 1, 17){
        c[l] = shift(c[l-1], l);
        d[l] = shift(d[l-1], l);
    }
}

void buildKey(){
    FOR(l, 1, 17){
        string tmp = c[l] + d[l];
        rep(i,48) k[l] += tmp[ pc2[i] - 1 ];
    }
}

void buildL0R0(){
    rep(l,32) L[0] += PT[ ip[l] - 1 ];
    FOR(l, 32, 64) R[0] += PT[ ip[l] - 1 ];
}

string getXor(string a, string b){
    string ret = "";
    rep(l,sz(a)){
        if(a[l] == b[l]) ret += '0';
        else ret += '1';
    }
    return ret;
}

int getRow(string x){
    string row = "";
    row += x[0];
    row += x[5];
    stringstream ii(row);
    int n;
    ii >> n;
    return b2d(n);
}

int getCol(string x){
    string col = "";
    FOR(l, 1, 5) col += x[l];
    stringstream ii(col);
    int n;
    ii >> n;
    return b2d(n);
}

string chqString(string a){
    if(sz(a) >= 4) return a;
    reverse(all(a));
    while(sz(a) < 4) a += '0';
    reverse(all(a));
    return a;
}

string fromS(string x){
    string tmp[10];
    int row[10], col[10];
    rep(l,10) tmp[l] = "";

    int i = 0, cnt = 0;
    rep(l,sz(x)){
        if(cnt >= 6){
            cnt = 0;
            i++;
        }
        cnt++;
        tmp[i] += x[l];
    }

    rep(l,8){
        row[l] = getRow(tmp[l]);
        col[l] = getCol(tmp[l]);
    }

    int result[10];
    rep(l,8) result[l] = s[l+1][row[l]][col[l]];
    string xx[10], ret = "";
    rep(l,10) xx[l] = "";
    rep(l,8) xx[l] = d2b(result[l]);
    rep(l,8) xx[l] = chqString(xx[l]);

    rep(l,8)
        for(auto i : xx[l]) ret += i;

    string xret = "";
    rep(l,32) xret += ret[p[l]-1];

    return xret;
}

string getRn(int pos){
    string ret = "", tmp = "";
    rep(l,48) tmp += R[pos-1][eBit[l]-1];
    ret = getXor(tmp, k[pos]);
    ret = fromS(ret);
    ret = getXor(ret, L[pos-1]);

    return ret;
}

void buildLR(){
    FOR(l, 1, 17){
        L[l] = R[l-1];
        R[l] = getRn(l);
    }
}

string getEncryptedText(){
    string tmp = R[16];
    tmp += L[16];
    string encrypt = "";
    rep(l,64) encrypt += tmp[ipI1[l]-1];
    return encrypt;
}

int main(){
    //std::ios_base::sync_with_stdio(0);cin.tie(0);
    FI;//FO;

    /*int t = 0, z = 0, len;
    int n = 0, k = 0, m = 0; int ans = 0;*/

    buildTables();

    iKey = "0001001100110100010101110111100110011011101111001101111111100111";
    PT = "1111111011011100101110100000000100100011010001010110000000010101";

    buildC0D0();
    buildCD();
    buildKey();
    buildL0R0();
    buildLR();

    cout << "msg: ";
    print(PT,64);
    NL;
    cout << "key: ";
    print(iKey,64);
    NL;

    NL;
    rep(l,80) cout << "=";
    NL;NL;

    rep(l,17){
        cout << "C" << l << " : ";
        print(c[l],28);
        NL;
        cout << "d" << l << " : ";
        print(d[l],28);
        NL;
        NL;
    }

    rep(l,80) cout << "=";
    NL;NL;

    FOR(l, 1, 17){
        cout << "K" << l << " : ";
        print(k[l],48);
        NL;NL;
    }

    NL;
    rep(l,80) cout << "=";
    NL;NL;

    rep(l,17){
        cout << "L" << l << " : ";
        print(L[l],32);
        NL;
        cout << "R" << l << " : ";
        print(R[l],32);
        NL;
        NL;
    }

    rep(l,80) cout << "=";
    NL;NL;

    cout << "Encrypted Message: ";
    print(getEncryptedText(),64);

    return 0;
}
