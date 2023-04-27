const test = require('tape')
const PhishingDetector = require('../src/detector.js')
const { testDomain } = require('./test.util.js')

function runTests () {
  test('config schema', (t) => {

    // return version with match
    testDomain(t, {
      domain: 'blocked-by-first.com',
      expected: true,
      version: 1,
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-by-first.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
      ],
    })

    // return name with match
    testDomain(t, {
      domain: 'blocked-by-first.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-by-first.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
      ],
    })
    // allow missing allowlist
    try {
      new PhishingDetector([
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
      ])
      t.pass('Passed validation')
    } catch (error) {
      t.fail(error.message)
    }

    // allow missing blocklist
    try {
      new PhishingDetector([
        {
          allowlist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
      ])
      t.pass('Passed validation')
    } catch (error) {
      t.fail(error.message)
    }

    // allow missing fuzzylist and tolerance
    try {
      new PhishingDetector([
        {
          allowlist: [],
          blocklist: [],
          name: 'first',
          version: 1
        },
      ])
      t.pass('Passed validation')
    } catch (error) {
      t.fail(error.message)
    }

    // allow missing tolerance
    try {
      new PhishingDetector([
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          version: 1
        },
      ])
      t.pass('Passed validation')
    } catch (error) {
      t.fail(error.message)
    }

    // throw when config is invalid
    const invalidConfigValues = [
      undefined,
      null,
      true,
      false,
      0,
      1,
      1.1,
      '',
      'test',
      () => {
        return {name: 'test', version: 1 }
      },
    ]
    for (const invalidValue of invalidConfigValues) {
      try {
        new PhishingDetector([invalidValue])
        t.fail('Did not fail validation')
      } catch (error) {
        t.equal(error.message, 'Invalid config')
      }
    }

    // throw when tolerance is provided without fuzzylist
    try {
      new PhishingDetector([
        {
          allowlist: [],
          blocklist: ['blocked-by-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1,
        },
      ])
      t.fail('Did not fail validation')
    } catch (error) {
      t.equal(error.message, 'Fuzzylist tolerance provided without fuzzylist')
    }

    // throw when config name is invalid
    const invalidNameValues = [
      undefined,
      null,
      true,
      false,
      0,
      1,
      1.1,
      '',
      () => {
        return {name: 'test', version: 1 }
      },
      {}
    ]
    for (const invalidValue of invalidNameValues) {
      try {
        new PhishingDetector([
          {
            allowlist: [],
            blocklist: ['blocked-by-first.com'],
            fuzzylist: [],
            name: invalidValue,
            tolerance: 2,
            version: 1
          },
        ])
        t.fail('Did not fail validation')
      } catch (error) {
        t.equal(error.message, "Invalid config parameter: 'name'")
      }
    }

    // throw when config version is invalid
    const invalidVersionValues = [
      undefined,
      null,
      true,
      false,
      '',
      () => {
        return {name: 'test', version: 1 }
      },
      {}
    ]
    for (const invalidValue of invalidVersionValues) {
      try {
        new PhishingDetector([
          {
            allowlist: [],
            blocklist: ['blocked-by-first.com'],
            fuzzylist: [],
            name: 'first',
            tolerance: 2,
            version: invalidValue
          },
        ])
        t.fail('Did not fail validation')
      } catch (error) {
        t.equal(error.message, "Invalid config parameter: 'version'")
      }
    }
    t.end()
  })

  test('multiple configs', (t) => {

    // allow no config
    testDomain(t, {
      domain: 'default.com',
      expected: false,
      options: [],
      type: 'all'
    })

    // allow by default
    testDomain(t, {
      domain: 'default.com',
      expected: false,
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'all'
    })

    // block origin in first config
    testDomain(t, {
      domain: 'blocked-by-first.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-by-first.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'blocklist'
    })

    // block origin in second config
    testDomain(t, {
      domain: 'blocked-by-second.com',
      expected: true,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: ['blocked-by-second.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'blocklist'
    })

    // prefer first config when origin blocked by both
    testDomain(t, {
      domain: 'blocked-by-both.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-by-both.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: ['blocked-by-both.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'blocklist'
    })

    // test first fuzzylist
    testDomain(t, {
      domain: 'fuzzy-first.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // test first fuzzylist at tolerance
    testDomain(t, {
      domain: 'fuzzy-firstab.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // allow first fuzzylist beyond tolerance
    testDomain(t, {
      domain: 'fuzzy-firstabc.com',
      expected: false,
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'all'
    })

    // test second fuzzylist
    testDomain(t, {
      domain: 'fuzzy-second.com',
      expected: true,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // test second fuzzylist at tolerance
    testDomain(t, {
      domain: 'fuzzy-secondab.com',
      expected: true,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // allow second fuzzylist past tolerance
    testDomain(t, {
      domain: 'fuzzy-secondabc.com',
      expected: false,
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'all'
    })

    // prefer first config when blocked by both fuzzylists
    testDomain(t, {
      domain: 'fuzzy-both.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-both.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-both.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // prefer first config when blocked by first and fuzzy blocked by second
    testDomain(t, {
      domain: 'blocked-first-fuzzy-second.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-first-fuzzy-second.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['blocked-first-fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'blocklist'
    })

    // prefer first config when fuzzy blocked by first and blocked by second
    testDomain(t, {
      domain: 'fuzzy-first-blocked-second.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first-blocked-second.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: ['fuzzy-first-blocked-second.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // allow origin that is allowed and not blocked on first config
    testDomain(t, {
      domain: 'allowed-first.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-first.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin that is allowed and not blocked on second config
    testDomain(t, {
      domain: 'allowed-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['allowed-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin that is blocklisted and allowlisted, both on first config
    testDomain(t, {
      domain: 'allowed-and-blocked-first.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-and-blocked-first.com'],
          blocklist: ['allowed-and-blocked-first.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin blocked by fuzzylist and allowlisted, both on first config
    testDomain(t, {
      domain: 'allowed-and-fuzzy-first.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-and-fuzzy-first.com'],
          blocklist: [],
          fuzzylist: ['allowed-and-fuzzy-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin that is blocklisted and allowlisted, both on second config
    testDomain(t, {
      domain: 'allowed-and-blocked-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['allowed-and-blocked-second.com'],
          blocklist: ['allowed-and-blocked-second.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin blocked by fuzzylist and allowlisted, both on second config
    testDomain(t, {
      domain: 'allowed-and-fuzzy-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['allowed-and-fuzzy-second.com'],
          blocklist: [],
          fuzzylist: ['allowed-and-fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin blocked by first config but allowedlisted by second
    testDomain(t, {
      domain: 'blocked-first-allowed-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-first-allowed-second.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['blocked-first-allowed-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin allowed by first config but blocked by second
    testDomain(t, {
      domain: 'allowed-first-blocked-second.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-first-blocked-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: ['allowed-first-blocked-second.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin fuzzylist blocked by first config but allowed by second
    testDomain(t, {
      domain: 'fuzzy-first-allowed-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first-allowed-second.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['fuzzy-first-allowed-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin allowed by first config but fuzzylist blocked by second
    testDomain(t, {
      domain: 'allowed-first-fuzzy-second.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-first-fuzzy-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['allowed-first-fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    t.end()
  })
}

module.exports = {
  runTests,
}
