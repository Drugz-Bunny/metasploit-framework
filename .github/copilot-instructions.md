# Metasploit Framework - AI Copilot Instructions

## Project Overview

Metasploit Framework is a penetration testing platform written in Ruby that provides:
- **Modules**: Reusable exploit, payload, post-exploitation, and auxiliary scanning components
- **Console**: Interactive msfconsole CLI for orchestrating exploitation workflows
- **Database**: PostgreSQL integration for storing scan results, credentials, hosts, services
- **RPC/Web Services**: REST API and RPC interface for programmatic access

## Architecture

### Core Component Hierarchy
```
lib/msf/
├── core/                 # Framework core: module classes, database, utilities
├── base/                 # Base classes for exploits, payloads, auxiliary modules
├── ui/                   # Console UI, command dispatchers
└── post/                 # Post-exploitation modules
modules/
├── exploits/             # Remote/local/physical exploitation modules
├── payloads/             # Payload generation (staged/stageless)
├── auxiliary/            # Scanners, fuzzers, DoS, brute-forcers
├── post/                 # Post-exploitation/lateral movement
├── encoders/             # Payload encoding/obfuscation
└── evasion/              # AV/EDR evasion modules
```

### Module Class Hierarchy
All modules inherit from specific base classes:
- `Msf::Exploit::Remote` - Network exploits (most common)
- `Msf::Exploit::Local` - Local privilege escalation/post-exploitation
- `Msf::Auxiliary` - Scanners, fuzzers, brute-forcers
- `Msf::Post` - Post-exploitation (execute after session established)
- `Msf::Payload::*` - Payload generators (stager/stage separation)

### Data Flow
```
Module Discovery → Initialization (update_info) → register_options 
→ check() → exploit()/run() → Session/Callback → Post Modules
                ↓
          Database (hosts, services, creds, vulns, notes)
```

## Module Development Patterns

### Essential Module Structure
```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking
  
  include Msf::Exploit::Remote::HttpClient  # Mix in required capabilities
  
  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'Vulnerability Name',
      'Description' => %q{ Multi-line description },
      'Author' => ['author1'],
      'License' => MSF_LICENSE,
      'Targets' => [
        ['Auto', { 'Platform' => 'windows', 'Arch' => [ARCH_X86] }]
      ],
      'DefaultTarget' => 0,
      'References' => [['CVE', '2023-XXXXX']],
      'Notes' => { 'Stability' => [CRASH_SAFE], 'Reliability' => [REPEATABLE_SESSION] }
    ))
    
    register_options([
      Opt::RPORT(445),
      OptString.new('TARGETURI', [true, 'Path', '/'])
    ])
  end
  
  def check
    # Return CheckCode::Appears, CheckCode::Safe, or CheckCode::Unknown
  end
  
  def exploit
    # Main exploitation logic
    send_request_cgi(...)
    handler  # Call handler() to establish session
  end
end
```

### Common Mixins & Their Purpose
- `Msf::Exploit::Remote::HttpClient` - HTTP requests
- `Msf::Exploit::Remote::SMB` - SMB protocol
- `Msf::Post::File` - File operations on compromised system
- `Msf::Post::Windows::Priv` - Windows privilege checks
- `Msf::Exploit::EXE` - EXE payload generation
- `Msf::Exploit::FileDropper` - Cleanup file dropping

## Key Files & Conventions

### Module Metadata Requirements
- **Rank**: Reliability ranking (`ExcellentRanking`, `GoodRanking`, etc.)
- **Notes.Stability**: Crash behavior (`CRASH_SAFE`, `CRASH_OS_DOWN`, `CRASH_APP_HANG`)
- **Notes.Reliability**: Session reliability (`REPEATABLE_SESSION`, `UNRELIABLE_SESSION`)
- **Notes.SideEffects**: (`IOC_IN_LOGS`, `SCREEN_EFFECTS`)

### Documentation
- Module documentation: `documentation/modules/{type}/{target_os}/{exploit_name}.md`
- Format: Markdown with Verification Steps section showing example commands
- Example: `documentation/modules/exploit/multi/http/confluence_rce.md`

### Testing & Validation
- Specs: `spec/lib/msf/modules/` and `spec/modules/`
- Use RSpec for unit tests; `acceptance/` tests use msfconsole integration
- Run: `bundle exec rspec spec/` or use `rake spec`
- Debugging: Use `pry` or `irb` inside msfconsole via `irb` command

### Database Integration
- Models: `app/models/` (ActiveRecord models for PostgreSQL)
- DB Operations: `lib/msf/core/db_manager/` manages hosts, services, creds, vulns
- Example: `framework.db.report_service(host: '192.168.1.1', port: 443, proto: 'tcp')`

## Development Workflow

### Setup
```bash
# Bundle dependencies (includes all gems)
bundle install
# or without database support:
bundle install --without db
```

### Running msfconsole
```bash
bundle exec msfconsole
```

### Creating/Testing Modules
1. Create module at `modules/{type}/{os}/{name}.rb`
2. Create documentation at `documentation/modules/{type}/{target_os}/{name}.md`
3. Test in msfconsole: `use module/path`, `show options`, `run`
4. Validate with `msftidy.rb` (linting tool): `ruby tools/dev/msftidy.rb modules/...rb`

### Debugging
- **Interactive breakpoint**: `require 'pry'; binding.pry` in code
- **Console interaction**: `console.interact` in acceptance tests
- **Debug logging**: Use `print_status()`, `print_error()`, `print_good()` not puts/p
- **Ruby console**: `irb` command inside msfconsole
- **View current module**: `show info` displays all metadata
- **View datastore**: `show options` or `setg LHOST 192.168.1.1`

## Project-Specific Patterns

### Payload Generation
- `generate()` method creates executable payloads
- Encoder chain applied via `-e` flag in msfconsole
- Stageless vs staged: Registry preference in module metadata
- `payload.encoded` gives encoded payload bytes

### Session Management
- Sessions stored in `framework.sessions[session_id]`
- Types: `Msf::Sessions::Meterpreter`, `Msf::Sessions::Shell`, `Msf::Sessions::VNC`
- `handler()` called after successful exploit to establish session

### Error Handling
- Don't raise Ruby exceptions in exploit modules; use `print_error()` + return
- Return false/nil from check() if verification fails
- Use `rescue` for network timeouts, not abort
- Exceptions logged to database via `framework.events.on_session_close`

## Convention Highlights

### Naming & Paths
- Exploit modules follow target OS/service: `modules/exploits/windows/smb/`, `modules/exploits/multi/http/`
- Post modules: `modules/post/{os}/{category}/{name}.rb`
- Filename: snake_case from CVE/vulnerability name

### Comments & Documentation
- Module headers include license + GitHub source
- Method signatures documented with YARD style: `# @param [Type] name description`
- No inline comment noise; code should be self-documenting

### Code Style
- Ruby style guide enforced via Rubocop
- Setup pre-commit hook: `gem install msftidy`, add to `.git/hooks/pre-commit`
- Max line length: 120 characters (enforced)

## Advanced Topics

### Database Schema
- Hosts, Services, Vulns, Creds stored in PostgreSQL
- Workspace isolation: Each workspace has separate data
- Loot/Notes: Arbitrary metadata storage
- Query via: `framework.db.hosts`, `framework.db.services({conditions: {port: 443}})`

### Session Callbacks
- `on_session_open` / `on_session_close` events
- Post-modules triggered after session established
- Access session: `session = client` inside post module

### Meterpreter Extensions
- Staged payload enables dynamic extension loading
- Extensions in `lib/rex/post/meterpreter/extensions/`
- Command dispatchers add console commands (e.g., `clipboard_get_data`)

## Common Pitfalls

❌ **Don't**:
- Modify modules without testing locally first
- Hardcode IPs/credentials in code
- Use `puts` instead of `print_status()`
- Assume target is vulnerable without `check()` method
- Leave TODO comments without action
- Submit untested code (even from LLMs/AI)

✅ **Do**:
- Include comprehensive `check()` method
- Add verification steps in documentation
- Test on actual vulnerable target before PR
- Follow 50/72 git commit message format
- Write RSpec tests for utility libraries
- Reference CVE/issue numbers in commits

## Where to Find Help

- **Documentation**: `docs/metasploit-framework.wiki/` (development guides)
- **Module examples**: `modules/exploits/multi/http/` (well-documented modules)
- **API reference**: Inline YARD docs; use `ri Msf::Exploit::Remote` in Ruby
- **Testing patterns**: `spec/lib/msf/modules/` for RSpec examples
