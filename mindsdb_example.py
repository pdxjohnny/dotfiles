import sys
import mindsdb_sdk

import snoop

@snoop
def main():
    question = " ".join(sys.argv[1:])
    print(f'Question is: {question }')

    if not question:
        sys.exit(1)

    # con = mindsdb_sdk.connect("https://mindsdb.pdxjohnny.localhost:443")
    con = mindsdb_sdk.connect("http://mindsdb.pdxjohnny.localhost:40795")

    # IMPORTANT: This code requires to set OPENAI_API_KEY as env variable

    try:
        agent = con.agents.create(f'new_demo_agent')
    except:
        agent = con.agents.get('new_demo_agent')

    # print('Adding Hooblyblob details...')
    # agent.add_file('./hooblyblob.txt', 'Details about the company Hooblyblob')

    print('Adding files...')
    agent.add_webpages(['https://pdxjohnny.github.io/maryisgod/'],
                    'Info on Alice can be found here')

    # print('Adding pdxjohnny.github.io...')
    # agent.add_webpages(['pdxjohnny.github.io'], 'Documentation for MindsDB')

    print('Agent ready to use.')
    answer = agent.completion([{'question': question, 'answer': None}])
    print(answer.content)


if __name__ == "__main__":
    main()
