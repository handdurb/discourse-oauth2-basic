# frozen_string_literal: true

class OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"

  # 禁用默认参数编码
  option :token_params, {
    parse: :json
  }

  # 核心方法：钉钉Token获取
  def build_access_token
    verifier = request.params['code']

    # 构造钉钉专用请求体
    raw_body = {
      clientId: client.id,
      clientSecret: client.secret,
      code: verifier,
      grantType: "authorization_code"
    }.to_json

    # 发送自定义JSON请求
    response = client.request(:post, client.token_url, body: raw_body) do |req|
      req.headers.update(
        "Content-Type" => "application/json",
        "Accept" => "application/json"
      )
    end

    # 手动解析钉钉响应并转换为标准OAuth2格式
    token_data = JSON.parse(response.body).deep_symbolize_keys
    ::OAuth2::AccessToken.from_hash(
      client,
      {
        access_token: token_data[:accessToken], # 钉钉 -> 标准
        refresh_token: token_data[:refreshToken], # 钉钉 -> 标准
        expires_in: token_data[:expireIn], # 钉钉 -> 标准
        token_type: "Bearer"
      }
    )
  end

  # 用户ID映射（使用unionId）
  uid do
    raw_info[:unionId] || raw_info["unionId"] || raw_info[:openId] || "unknown"
  end

  # 用户信息映射
  info do
    {
      name: raw_info[:nick] || raw_info["nick"] || "钉钉用户",
      email: raw_info[:email] || raw_info["email"] || "#{raw_info[:unionId]}@dingtalk.fallback",
      image: raw_info[:avatarUrl] || raw_info["avatarUrl"]
    }
  end

  # 获取钉钉用户信息（修复请求头）
  def raw_info
    @raw_info ||= begin

                    user_info_url = SiteSetting.oauth2_user_json_url

                    conn = Faraday.new(
                      url: user_info_url,
                      headers: {
                        'x-acs-dingtalk-access-token' => access_token.token,
                        'x-acs-dingtalk-org-id' => SiteSetting.oauth2_client_corpid,
                        'Accept' => 'application/json'
                      }
                    ) do |f|
                      f.request :json
                      f.response :json
                    end

                    # 添加调试日志
                    Rails.logger.info "用户信息接口URL: #{user_info_url}"
                    Rails.logger.info "请求头: #{conn.headers}"

                    response = conn.get("")
                    raise StandardError, response.body['message'] if response.status != 200

                    response.body.deep_symbolize_keys
                  rescue => e
                    Rails.logger.error "钉钉用户信息获取失败: #{e.message}"
                    {}
                  end
  end

  uid do
    if path = SiteSetting.oauth2_callback_user_id_path.split(".")
      recurse(access_token, [*path]) if path.present?
    end
  end

  info do
    if paths = SiteSetting.oauth2_callback_user_info_paths.split("|")
      result = Hash.new
      paths.each do |p|
        segments = p.split(":")
        if segments.length == 2
          key = segments.first
          path = [*segments.last.split(".")]
          result[key] = recurse(access_token, path)
        end
      end
      result
    end
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end

  def recurse(obj, keys)
    return nil if !obj
    k = keys.shift
    result = obj.respond_to?(k) ? obj.send(k) : obj[k]
    keys.empty? ? result : recurse(result, keys)
  end
end
