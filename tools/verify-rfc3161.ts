#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import {
  TimestampReceiptError,
  verifyTimestampReceipt,
} from './rfc3161.ts';

interface CliOptions {
  dataPath: string;
  receiptPath: string;
  caPath: string;
  untrustedPath?: string;
  policy?: string;
  roundTime: string;
  maxAccuracyMs?: number;
}

const USAGE = `Usage: npm run verify:rfc3161 -- --data FILE --receipt FILE --ca FILE --round-time VALUE [options]

Verify an RFC 3161 timestamp receipt against exact data bytes, the configured
TSA trust bundle, and a drand round time. VALUE may be an ISO-8601 timestamp,
epoch seconds, or epoch milliseconds.

Options:
  --data FILE       Archived commitment JSON bytes covered by the receipt
  --receipt FILE    RFC 3161 .tsr response
  --ca FILE         Trusted TSA CA bundle (required)
  --untrusted FILE  TSA signing/intermediate certificate bundle
  --policy OID      Optional RFC 3161 TSA policy OID
  --round-time V    drand target round time; receipt time must be strictly earlier
  --max-accuracy-ms N
                    Required only when the receipt omits accuracy; conservative
                    upper-bound error allowance in milliseconds
  --help            Show this help

The command prints one JSON result and exits 0 only when the SHA-256 message
imprint, TSA signature/certificate chain, and pre-round timestamp all verify.
`;

function usageError(message: string): never {
  throw new TimestampReceiptError('TSA_USAGE_INVALID', `${message}\n\n${USAGE}`);
}

function requireOption(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith('--')) usageError(`${option} requires a value`);
  return value;
}

function parseArgs(args: string[]): CliOptions | 'help' {
  const parsed: Partial<CliOptions> = {};
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option === '--help' || option === '-h') return 'help';
    if (option === '--data') {
      parsed.dataPath = requireOption(args, index, option);
      index += 1;
    } else if (option === '--receipt') {
      parsed.receiptPath = requireOption(args, index, option);
      index += 1;
    } else if (option === '--ca') {
      parsed.caPath = requireOption(args, index, option);
      index += 1;
    } else if (option === '--untrusted') {
      parsed.untrustedPath = requireOption(args, index, option);
      index += 1;
    } else if (option === '--policy') {
      parsed.policy = requireOption(args, index, option);
      index += 1;
    } else if (option === '--round-time') {
      parsed.roundTime = requireOption(args, index, option);
      index += 1;
    } else if (option === '--max-accuracy-ms') {
      const value = requireOption(args, index, option);
      const parsedValue = Number(value);
      if (!Number.isFinite(parsedValue) || parsedValue < 0) {
        usageError('--max-accuracy-ms must be a finite non-negative number');
      }
      parsed.maxAccuracyMs = parsedValue;
      index += 1;
    } else {
      usageError(`unknown option: ${option}`);
    }
  }
  if (!parsed.dataPath || !parsed.receiptPath || !parsed.caPath || !parsed.roundTime) {
    usageError('--data, --receipt, --ca, and --round-time are required');
  }
  return parsed as CliOptions;
}

function main(): void {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options === 'help') {
      process.stdout.write(USAGE);
      return;
    }
    const result = verifyTimestampReceipt(options);
    process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
  } catch (error) {
    const code = error instanceof TimestampReceiptError ? error.code : 'TSA_VERIFICATION_FAILED';
    const detail = error instanceof Error ? error.message : String(error);
    process.stdout.write(`${JSON.stringify({ ok: false, code, detail })}\n`);
    process.exitCode = 1;
  }
}

if (resolve(process.argv[1] || '') === fileURLToPath(import.meta.url)) main();
