import {defineConfig} from '@playwright/test';
import {existsSync} from 'node:fs';
export default defineConfig({
  testDir:'./tests',workers:1,timeout:60000,fullyParallel:false,
  use:{headless:true,trace:'off',screenshot:'off',video:'off',launchOptions:{
    executablePath:process.env.CHROME_BIN || (existsSync('/usr/bin/google-chrome')?'/usr/bin/google-chrome':undefined)
  }},
});
