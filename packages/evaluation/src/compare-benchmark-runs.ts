import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { BenchmarkPredictionSchema, type BenchmarkPrediction } from './index'
import { compareBenchmarkSummaries } from './benchmark-runtime'

interface SummaryFile {
  readonly summary: {
    readonly overall: { readonly precision: number; readonly recall: number; readonly f1: number }
    readonly safety: { readonly passed: boolean }
  }
}

function parseInputs(argv: string[]): string[] {
  const inputs: string[] = []
  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index]
    if (value === '--inputs' || value === '--input') {
      while (argv[index + 1] && !argv[index + 1]!.startsWith('--')) {
        inputs.push(
          ...argv[index + 1]!
            .split(/[,\s]+/u)
            .map((item) => item.trim())
            .filter(Boolean)
            .map((item) => resolve(item))
        )
        index += 1
      }
      continue
    }
    throw new Error(`Unknown or incomplete argument: ${value ?? ''}`)
  }
  if (inputs.length < 2) {
    throw new Error('compare-benchmark-runs requires at least two --inputs directories.')
  }
  return inputs
}

const directories = parseInputs(process.argv)
const runs = await Promise.all(
  directories.map(async (directory, index) => {
    const predictions = (
      JSON.parse(await readFile(resolve(directory, 'predictions.json'), 'utf8')) as unknown[]
    ).map((item) => BenchmarkPredictionSchema.parse(item)) as BenchmarkPrediction[]
    const summaryFile = JSON.parse(
      await readFile(resolve(directory, 'summary.json'), 'utf8')
    ) as SummaryFile
    return {
      label: `run${index + 1}:${directory}`,
      predictions,
      safetyPassed: summaryFile.summary.safety.passed,
      precision: summaryFile.summary.overall.precision,
      recall: summaryFile.summary.overall.recall,
      f1: summaryFile.summary.overall.f1
    }
  })
)

const comparison = compareBenchmarkSummaries({ runs })
console.log(JSON.stringify({ directories, ...comparison }, null, 2))
if (comparison.mismatches.length > 0) {
  process.exitCode = 1
}
