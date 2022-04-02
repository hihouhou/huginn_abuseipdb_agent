module Agents
  class AbuseipdbAgent < Agent
    include FormConfigurable
    can_dry_run!
    no_bulk_receive!
    default_schedule "never"

    description do
      <<-MD
      The Abuseipdb Agent allows you to utilize the AbuseIPDB API for creating report/check/etc actions.

      `debug` is used for verbose mode.

      `type` is for the wanted action like check/blacklist/report/check-block/bulk-report/clear-address.

      `categories` is for the attack categories(At least one category is required).

      `token` is the database's name.

      `limit` is a parameter for only returning reports within the last x amount of days.

       If `emit_events` is set to `true`, the server response will be emitted as an Event. No data processing
       will be attempted by this Agent, so the Event's "body" value will always be raw text.

      `data` is the payload (https://docs.abuseipdb.com/#introduction).

      `expected_receive_period_in_days` is used to determine if the Agent is working. Set it to the maximum number of days
      that you anticipate passing without this Agent receiving an incoming Event.
      MD
    end

    event_description <<-MD
      Events look like this:

          {
            "data": {
              "ipAddress": "127.0.0.1",
              "abuseConfidenceScore": 52
            }
          }
    MD

    def default_options
      {
        'type' => '',
        'token' => '',
        'limit' => '',
        'categories' => '',
        'data' => '',
        'debug' => 'false',
        'emit_events' => 'false',
        'expected_receive_period_in_days' => '2',
      }
    end

    form_configurable :debug, type: :boolean
    form_configurable :emit_events, type: :boolean
    form_configurable :expected_receive_period_in_days, type: :string
    form_configurable :type, type: :array, values: ['check', 'blacklist', 'report', 'check-block', 'bulk-report', 'clear-address']
    form_configurable :token, type: :string
    form_configurable :limit, type: :string
    form_configurable :categories, type: :string
    form_configurable :data, type: :string
    def validate_options
      errors.add(:base, "type has invalid value: should be 'check', 'blacklist', 'report', 'check-block', 'bulk-report' or 'clear-address'") if interpolated['type'].present? && !%w(check blacklist report check-block bulk-report clear-address).include?(interpolated['type'])

      errors.add(:base, "categories must be provided") if interpolated['type'] == 'report' && !options['categories'].present?

      errors.add(:base, "limit must be provided") if interpolated['type'] == 'check' && !options['limit'].present?

      unless options['token'].present?
        errors.add(:base, "token is a required field")
      end

      unless options['data'].present?
        errors.add(:base, "data is a required field")
      end

      if options.has_key?('emit_events') && boolify(options['emit_events']).nil?
        errors.add(:base, "if provided, emit_events must be true or false")
      end

      if options.has_key?('debug') && boolify(options['debug']).nil?
        errors.add(:base, "if provided, debug must be true or false")
      end

      unless options['expected_receive_period_in_days'].present? && options['expected_receive_period_in_days'].to_i > 0
        errors.add(:base, "Please provide 'expected_receive_period_in_days' to indicate how many days can pass before this Agent is considered to be not working")
      end
    end

    def working?
      event_created_within?(options['expected_receive_period_in_days']) && !recent_error_logs?
    end

    def receive(incoming_events)
      incoming_events.each do |event|
        interpolate_with(event) do
          log event
          trigger_action
        end
      end
    end

    def check
      trigger_action
    end

    private

    def checkip()

      uri = URI.parse("https://api.abuseipdb.com/api/v2/check")
      params = JSON.parse(interpolated['data'])
      uri.query = URI.encode_www_form(params)
      log uri.query
      log uri
      request = Net::HTTP::Get.new(uri)
      request["Key"] = "#{interpolated['token']}"
      request["Accept"] = "application/json"
      request.set_form_data(
        "maxAgeInDays" => "#{interpolated['limit']}",
      )
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log "request status : #{response.code}"

      if interpolated['debug'] == 'true'
        log "response.body"
        log response.body
      end
    end

    def blacklist()

      uri = URI.parse("https://api.abuseipdb.com/api/v2/blacklist")
      request = Net::HTTP::Get.new(uri)
      request["Key"] = "#{interpolated['token']}"
      request["Accept"] = "application/json"
#      request.set_form_data(
#        "confidenceMinimum" => "90",
#      )
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log "request status : #{response.code}"

      if interpolated['debug'] == 'true'
        log "response.body"
        log response.body
      end
    end

    def report()

      uri = URI.parse("https://api.abuseipdb.com/api/v2/report")
      params = JSON.parse(interpolated['data'])
      uri.query = URI.encode_www_form(params)
      request = Net::HTTP::Post.new(uri)
      request["Key"] = "#{interpolated['token']}"
      request["Accept"] = "application/json"
      request.set_form_data(
        "categories" => "#{interpolated['categories']}",
      )
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log "request status : #{response.code}"

      if interpolated['debug'] == 'true'
        log "response.body"
        log response.body
      end
    end

    def check_block()

      uri = URI.parse("https://api.abuseipdb.com/api/v2/check-block")
      params = JSON.parse(interpolated['data'])
      uri.query = URI.encode_www_form(params)
      request = Net::HTTP::Get.new(uri)
      request["Key"] = "#{interpolated['token']}"
      request["Accept"] = "application/json"
      request.set_form_data(
        "maxAgeInDays" => "#{interpolated['limit']}",
      )
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log "request status : #{response.code}"

      if interpolated['debug'] == 'true'
        log "response.body"
        log response.body
      end
    end

    def bulk_report()

      uri = URI.parse("https://api.abuseipdb.com/api/v2/report")
      request = Net::HTTP::Post.new(uri)
      request["Key"] = ""
      request["Accept"] = "application/json"
      request.set_form_data(
        "categories" => "18,22",
      )
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log "request status : #{response.code}"

      if interpolated['debug'] == 'true'
        log "response.body"
        log response.body
      end
    end

    def clear_address()

      uri = URI.parse("https://api.abuseipdb.com/api/v2/clear-address")
      params = JSON.parse(interpolated['data'])
      uri.query = URI.encode_www_form(params)
      request = Net::HTTP::Delete.new(uri)
      request["Key"] = "#{interpolated['token']}"
      request["Accept"] = "application/json"
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log "request status : #{response.code}"

      if interpolated['debug'] == 'true'
        log "response.body"
        log response.body
      end
    end

    def trigger_action

      case interpolated['type']
      when "check"
        checkip()
      when "blacklist"
        blacklist()
      when "report"
        report()
      when "check-block"
        check_block()
      when "bulk-report"
        bulk_report()
      when "clear-address"
        clear_address()
      else
        log "Error: type has an invalid value (#{type})"
      end
    end
  end
end
