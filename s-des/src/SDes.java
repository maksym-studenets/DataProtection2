import java.util.ArrayList;

/**
 * S-DES encryption algorithm implementation
 */
public class SDes {
    private int K1, K2;
    private ArrayList<String> bytesAll;

    // permutations
    //
    private static final int P10[] = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    private static final int P10max = 10;

    private static final int P8[] = { 6, 3, 7, 4, 8, 5, 10, 9};
    private static final int P8max = 10;

    private static final int P4[] = { 2, 4, 3, 1};
    private static final int P4max = 4;

    private static final int IP[] = { 2, 6, 3, 1, 4, 8, 5, 7};
    private static final int maxIP = 8;

    private static final int IPI[] = { 4, 1, 3, 5, 7, 2, 8, 6};
    private static final int maxIPI = 8;

    private static final int EP[] = { 4, 1, 2, 3, 2, 3, 4, 1};
    private static final int maxEP = 4;

    private static final int S0[][] = {
            { 1, 0, 3, 2},
            { 3, 2, 1, 0},
            { 0, 2, 1, 3},
            { 3, 1, 3, 2}
    };

    private static final int S1[][] = {
            { 0, 1, 2, 3},
            { 2, 0, 1, 3},
            { 3, 0, 1, 0},
            { 2, 1, 0, 3}
    };

    public SDes( int K) {
        K = permute( K, P10, P10max);

        // 5-bit parts of K
        //
        int t1 = (K >> 5) & 0x1F;
        int t2 = K & 0x1F;

        // LS-1
        //
        t1 = ((t1 & 0xF) << 1) | ((t1 & 0x10) >> 4);
        t2 = ((t2 & 0xF) << 1) | ((t2 & 0x10) >> 4);

        K1 = permute( (t1 << 5) | t2, P8, P8max);

        // LS-2
        //
        t1 = ((t1 & 0x7) << 2) | ((t1 & 0x18) >> 3);
        t2 = ((t2 & 0x7) << 2) | ((t2 & 0x18) >> 3);

        K2 = permute( (t1 << 5) | t2, P8, P8max);

        System.out.print("1st subkey: ");
        printBytes(K1, 8);
        System.out.println("");
        System.out.print("2nd subkey: ");
        printBytes(K2, 8);
        System.out.println("");
    }

    // permute bits
    //
    public int permute( int x, int p[], int pmax) {
        int y = 0;

        for (int aP : p) {
            y <<= 1;
            y |= (x >> (pmax - aP)) & 1;
        }

        return y;
    }

    // F function
    //
    private int F(int R, int K) {
        int t = permute( R, EP, maxEP) ^ K;
        int t0 = (t >> 4) & 0xF;
        int t1 = t & 0xF;

        t0 = S0[ ((t0 & 0x8) >> 2) | (t0 & 1) ][ (t0 >> 1) & 0x3 ];
        t1 = S1[ ((t1 & 0x8) >> 2) | (t1 & 1) ][ (t1 >> 1) & 0x3 ];

        t = permute( (t0 << 2) | t1, P4, P4max);

        return t;
    }

    // fK function
    //
    private int fK(int m, int K) {
        int L = (m >> 4) & 0xF;
        int R = m & 0xF;

        return ((L ^ F(R,K)) << 4) | R;
    }

    // switch function
    //
    private int SW(int x) {
        return ((x & 0xF) << 4) | ((x >> 4) & 0xF);
    }

    public byte process(int m, boolean isEncryption) {
        m = permute(m, IP, maxIP);
        if (isEncryption) {
            m = fK(m, K1);
            m = SW(m);
            m = fK(m, K2);
            m = permute(m, IPI, maxIPI);
        } else {
            m = fK(m, K2);
            m = SW(m);
            m = fK(m, K1);
            m = permute(m, IPI, maxIPI);
        }

        return (byte) m;
    }

    // encrypt one byte
    //
    @Deprecated
    public byte encrypt( int m) {
        m = permute( m, IP, maxIP);
        m = fK( m, K1);
        m = SW( m);
        m = fK( m, K2);
        m = permute( m, IPI, maxIPI);

        return (byte) m;
    }

    // decrypt one byte
    //
    @Deprecated
    public byte decrypt( int m) {
        m = permute( m, IP, maxIP);
        m = fK( m, K2);
        m = SW( m);
        m = fK( m, K1);
        m = permute( m, IPI, maxIPI);

        return (byte) m;
    }

    // print n bits in binary
    //
    public void printBytesOld(int x, int n) {
        int mask = 1 << (n - 1);

        while( mask > 0) {
            System.out.print( ((x & mask) == 0) ? '0' : '1');
            mask >>= 1;
        }
    }

    public void printBytes(int sequence, int n) {
        ArrayList<String> bytes = new ArrayList<>();
        bytesAll = new ArrayList<>();
        StringBuilder builder = new StringBuilder();
        int mask = 1 << (n - 1);
        while (mask > 0) {
            //bytes.add(((sequence & mask) == 0) ? '0' : '1');
            bytes.add(String.valueOf(((sequence & mask) == 0) ? '0' : '1'));
            builder.append(String.valueOf(((sequence & mask) == 0) ? '0' : '1'));
            mask >>= 1;
        }

        bytesAll.add(builder.toString());
        bytes.forEach(System.out::print);
    }

    public static void printKey(int key) {
        StringBuilder builder = new StringBuilder();
        int n = 2;

        int mask = 1 << (n - 1);
        while (mask > 0) {
            builder.append(String.valueOf(((key & mask) == 0) ? '0' : '1'));
            mask >>= 1;
        }
        System.out.println(builder.toString());
    }

    public String getEncryptedMessage(int[] encrypted) {
        int n = 8;
        StringBuilder builder = new StringBuilder();

        for (int value : encrypted) {
            int mask = 1 << (n - 1);
            while (mask > 0) {
                builder.append(String.valueOf(((value & mask) == 0) ? '0' : '1'));
                mask >>= 1;
            }
            builder.append(" ");
        }

        return builder.toString();
    }

    public String get10BitValues(int sequence) {
        int n = 10;
        StringBuilder stringBuilder = new StringBuilder();
        int mask = 1 << (n - 1);
        while (mask > 0) {
            stringBuilder.append(String.valueOf(((sequence & mask) == 0) ? '0' : '1'));
            mask >>= 1;
        }
        return stringBuilder.toString();
    }

    public ArrayList<String> getBytes() {
        return bytesAll;
    }
}
