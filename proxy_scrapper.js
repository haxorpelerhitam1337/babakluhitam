const fs = require("fs");
const path = require("path");
const utils = require("./lib/utils");

const fineproxy = require("./scrapper/fineproxy");
const ProxyDB = require("./scrapper/ProxyDB");
const FreeProxyList = require("./scrapper/FreeProxyList");
const ProxyScrape = require("./scrapper/ProxyScrape");
const IPRoyal = require("./scrapper/IPRoyal");
const Hidemn = require("./scrapper/Hidemn");
const xreverselabs = require("./scrapper/xreverselabs");
const ProxyRack = require("./scrapper/ProxyRack");
const ProxyBros = require("./scrapper/ProxyBros");
const geonode = require("./scrapper/geonode");
const randomProxyUrls = require("./scrapper/random_proxy");
const xcddos = require("./scrapper/xcddos");
const ProxyElite = require("./scrapper/ProxyElite");
const shuffleArray = (array) => {
  const newArray = [...array];
  for (let i = newArray.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
  }
  return newArray;
};
const createScraperWrapper = (scraper, lineNumber, updateFn) => {
  return async () => {
    try {
      let currentCount = 0;
      let displayCount = 0;
      let updateInterval = null;
      const reportProgress = (count) => {
        currentCount = count;
      };
      updateInterval = setInterval(() => {
        if (displayCount < currentCount) {
          displayCount++;
          updateFn(lineNumber, `${scraper.name.padEnd(20)} >> found ${displayCount} proxies so far...`);
        }
      }, 10);
      const result = await scraper.fn(reportProgress);
      clearInterval(updateInterval);
      updateFn(lineNumber, `${scraper.name.padEnd(20)} >> got (${result.valid}) proxies `);
      
      return { ...result, name: scraper.name };
    } catch (error) {
      updateFn(lineNumber, `${scraper.name.padEnd(20)} >> error: ${error.message}`);
      return { total: 0, valid: 0, indo: 0, name: scraper.name };
    }
  };
};
const main = async () => {
  try {
    console.log(`
██████╗░██████╗░░█████╗░██╗░░██╗██╗░░░██╗  ░██████╗░█████╗░██████╗░░█████╗░██████╗░██████╗░███████╗██████╗░
██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝╚██╗░██╔╝  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝██████╔╝██║░░██║░╚███╔╝░░╚████╔╝░  ╚█████╗░██║░░╚═╝██████╔╝███████║██████╔╝██████╔╝█████╗░░██████╔╝
██╔═══╝░██╔══██╗██║░░██║░██╔██╗░░░╚██╔╝░░  ░╚═══██╗██║░░██╗██╔══██╗██╔══██║██╔═══╝░██╔═══╝░██╔══╝░░██╔══██╗
██║░░░░░██║░░██║╚█████╔╝██╔╝╚██╗░░░██║░░░  ██████╔╝╚█████╔╝██║░░██║██║░░██║██║░░░░░██║░░░░░███████╗██║░░██║
╚═╝░░░░░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░  ╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░░░░╚═╝░░░░░╚══════╝╚═╝░░╚═╝

- Developed By Eclipse Security labs    
      `);
    console.log("🚀 Starting proxy scraper with Indonesian IP filtering");
    const startTime = Date.now();
    utils.initFiles();
    const scrapers = [
      { id: 1, name: "Fineproxy", fn: fineproxy },
      { id: 2, name: "ProxyDB", fn: ProxyDB },
      { id: 3, name: "FreeProxyList", fn: FreeProxyList },
      { id: 4, name: "ProxyScrape", fn: ProxyScrape },
      { id: 5, name: "IPRoyal", fn: IPRoyal },
      { id: 6, name: "Hidemn", fn: Hidemn },
      { id: 7, name: "xreverselabs", fn: xreverselabs },
      { id: 8, name: "ProxyRack", fn: ProxyRack },
      { id: 9, name: "ProxyBros", fn: ProxyBros },
      { id: 10, name: "geonode", fn: geonode },
      { id: 11, name: "Random URLs", fn: randomProxyUrls },
      { id: 12, name: "XCDDOS ID", fn: xcddos },
      { id: 13, name: "ProxyElite", fn: ProxyElite }
    ];
    const shuffledOrder = shuffleArray([...scrapers]);
    const updateLine = (lineNumber, text) => {
      process.stdout.write('\r');
      process.stdout.write(`\x1B[${lineNumber}A`);
      process.stdout.write('\x1B[2K');
      process.stdout.write(text);
      process.stdout.write(`\x1B[${lineNumber}B`);
      process.stdout.write('\r');
    };
    shuffledOrder.forEach((scraper) => {
      console.log(`${scraper.name.padEnd(20)} >> running...`);
    });
    const originalConsoleLog = console.log;
    const originalConsoleError = console.error;
    const originalConsoleWarn = console.warn;
    const originalConsoleInfo = console.info;
    console.log = () => {};
    console.error = () => {};
    console.warn = () => {};
    console.info = () => {};
    const lineMap = {};
    shuffledOrder.forEach((scraper, index) => {
      lineMap[scraper.id] = shuffledOrder.length - index;
    });
    const scraperPromises = scrapers.map((scraper) => {
      const lineNumber = lineMap[scraper.id];
      return createScraperWrapper(scraper, lineNumber, updateLine)();
    });
    const results = await Promise.all(scraperPromises);
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    console.warn = originalConsoleWarn;
    console.info = originalConsoleInfo;
    let totalProxies = 0;
    let validProxies = 0;
    let indonesianProxies = 0;
    for (const result of results) {
      totalProxies += result.total;
      validProxies += result.valid;
      indonesianProxies += result.indo;
    }
    const totalTimeElapsed = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log("\n");
    console.log("━".repeat(80));
    console.log(`✅ Proxy scraping completed in ${totalTimeElapsed}s`);
    console.log("━".repeat(80));
    console.log(`📊 Total proxies : ${totalProxies}`);
    console.log(`📊 Valid Proxies : ${utils.writtenProxies.size}`);
    console.log("━".repeat(80));
    console.log(`📁 Saved To : ${utils.outputFile}`);
    console.log(`📁 Indonesian proxies : ${utils.indonesianOutputFile}`);
    console.log("\n📊 Results by scraper (sorted by most proxies):");
    results
      .sort((a, b) => b.total - a.total)
      .forEach(result => {
        console.log(`${result.name.padEnd(20)} >> got (${result.total.toString().padStart(5)}) proxies`);
      });
  } catch (error) {
    console.error("❌ Fatal error:", error.message);
  }
};
const createSampleUrlsFile = () => {
  const filePath = "./scrapper/url/urls.txt";
  if (!fs.existsSync(filePath)) {
    if (!fs.existsSync("./scrapper/url")) {
      fs.mkdirSync("./scrapper/url");
    }
    
    fs.writeFileSync(filePath);
    console.log(`Created sample ${filePath} file with common proxy URLs`);
  }
};
if (!fs.existsSync("./scrapper")) {
  fs.mkdirSync("./scrapper");
}
createSampleUrlsFile();
main();