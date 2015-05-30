using GostPlugin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GostECB_Test
{
    class Program
    {
        static void Main(string[] args)
        {
            var data = new byte[8];
            var key = new byte[32];
            var enc = new byte[8];

            var r = new Random();
            r.NextBytes(key);

            var ecb = new GostECB(key, GostECB.SBox_Test);

            Stopwatch sw = new Stopwatch();

            sw.Start();
            for (int i = 0; i < 1048576; i++)
            {
                r.NextBytes(data);
                enc = ecb.Process(data);
            }
            sw.Stop();
            Console.WriteLine("Speed {0:F2} MB/s", 8192.0 / sw.ElapsedMilliseconds);
            Console.ReadKey();

        }
    }
}
